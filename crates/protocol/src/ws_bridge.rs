//! Turn a WebSocket into a plain byte stream for Yamux.
//!
//! A task owns the WebSocket and pumps bytes between it and one half of a
//! `tokio::io::duplex`. Each write from the duplex becomes one binary message;
//! binary messages are concatenated on read. The task also sends a ping every
//! `ping_interval` and closes the pipe after ~2.5 intervals without a pong.
//! Text frames are ignored. No nested RFC 6455: only bytes cross this pipe.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

const DUPLEX_BUFFER: usize = 256 * 1024;
const READ_CHUNK: usize = 64 * 1024;

pub fn bridge<S>(ws: WebSocketStream<S>, ping_interval: Duration) -> (DuplexStream, JoinHandle<()>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (app_side, pump_side) = tokio::io::duplex(DUPLEX_BUFFER);
    let handle = tokio::spawn(async move {
        let (mut sink, mut stream) = ws.split();
        let (mut rd, mut wr) = tokio::io::split(pump_side);
        let mut buf = vec![0u8; READ_CHUNK];
        let mut ticker = tokio::time::interval(ping_interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        ticker.tick().await;
        let mut last_pong = Instant::now();
        let dead_after = ping_interval * 2 + ping_interval / 2;

        loop {
            tokio::select! {
                msg = stream.next() => match msg {
                    Some(Ok(Message::Binary(data))) => {
                        if wr.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Pong(_))) => last_pong = Instant::now(),
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                    // Pings are answered by tungstenite on the next flush.
                    Some(Ok(_)) => {}
                },
                n = rd.read(&mut buf) => match n {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if sink.send(Message::Binary(buf[..n].to_vec().into())).await.is_err() {
                            break;
                        }
                    }
                },
                _ = ticker.tick() => {
                    if last_pong.elapsed() > dead_after {
                        tracing::debug!("websocket pong timeout");
                        break;
                    }
                    if sink.send(Message::Ping(Vec::new().into())).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = sink.close().await;
        let _ = wr.shutdown().await;
    });
    (app_side, handle)
}
