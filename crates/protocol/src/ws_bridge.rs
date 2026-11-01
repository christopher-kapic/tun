//! Turn a WebSocket into a plain byte stream for Yamux.
//!
//! Two tasks own the WebSocket halves and pump bytes between it and one half
//! of a `tokio::io::duplex`, one per direction, so a slow write toward the
//! peer never stalls reads from it (and vice versa). The writer drains all the
//! bytes already waiting in the pipe into binary messages before one flush, so
//! several Yamux frames written in quick succession cost one TLS write. Binary
//! messages are concatenated on read; text frames are ignored.
//!
//! Keepalive: the writer sends a ping every `ping_interval`; the pipe closes
//! after ~2.5 intervals without hearing any frame from the peer (any frame
//! counts, so a busy link is never declared dead because its pong is queued
//! behind data). No nested RFC 6455: only bytes cross this pipe.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures_util::{FutureExt, SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

const DUPLEX_BUFFER: usize = 256 * 1024;
const READ_CHUNK: usize = 64 * 1024;
/// Most bytes fed between flushes (bounds latency of the first message).
const MAX_BATCH: usize = 256 * 1024;

pub fn bridge<S>(ws: WebSocketStream<S>, ping_interval: Duration) -> (DuplexStream, JoinHandle<()>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (app_side, pump_side) = tokio::io::duplex(DUPLEX_BUFFER);
    let handle = tokio::spawn(async move {
        let (mut sink, mut stream) = ws.split();
        let (mut rd, mut wr) = tokio::io::split(pump_side);
        let started = Instant::now();
        // Milliseconds since `started` when the peer was last heard from.
        let heard = Arc::new(AtomicU64::new(0));

        let mut inbound = {
            let heard = heard.clone();
            tokio::spawn(async move {
                while let Some(msg) = stream.next().await {
                    let Ok(msg) = msg else { break };
                    heard.store(started.elapsed().as_millis() as u64, Ordering::Relaxed);
                    match msg {
                        Message::Binary(data) => {
                            if wr.write_all(&data).await.is_err() {
                                break;
                            }
                        }
                        Message::Close(_) => break,
                        // Pings are answered by tungstenite on the next flush.
                        _ => {}
                    }
                }
                let _ = wr.shutdown().await;
            })
        };

        let mut buf = vec![0u8; READ_CHUNK];
        let mut ticker = tokio::time::interval(ping_interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        ticker.tick().await;
        let dead_after = (ping_interval * 2 + ping_interval / 2).as_millis() as u64;

        'outer: loop {
            tokio::select! {
                n = rd.read(&mut buf) => {
                    let n = match n { Ok(0) | Err(_) => break, Ok(n) => n };
                    if sink.feed(Message::Binary(Bytes::copy_from_slice(&buf[..n]))).await.is_err() {
                        break;
                    }
                    // Whatever else Yamux has already written goes out with it.
                    let mut batched = n;
                    let mut eof = false;
                    while batched < MAX_BATCH {
                        match rd.read(&mut buf).now_or_never() {
                            Some(Ok(0)) | Some(Err(_)) => { eof = true; break; }
                            Some(Ok(m)) => {
                                if sink.feed(Message::Binary(Bytes::copy_from_slice(&buf[..m]))).await.is_err() {
                                    break 'outer;
                                }
                                batched += m;
                            }
                            None => break,
                        }
                    }
                    if sink.flush().await.is_err() || eof {
                        break;
                    }
                }
                _ = ticker.tick() => {
                    let silent = (started.elapsed().as_millis() as u64).saturating_sub(heard.load(Ordering::Relaxed));
                    if silent > dead_after {
                        tracing::debug!("websocket keepalive timeout");
                        break;
                    }
                    if sink.send(Message::Ping(Bytes::new())).await.is_err() {
                        break;
                    }
                }
                _ = &mut inbound => break,
            }
        }
        let _ = sink.close().await;
        inbound.abort();
    });
    (app_side, handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_tungstenite::tungstenite::protocol::Role;

    async fn pair(ping: Duration) -> (DuplexStream, DuplexStream) {
        let (a, b) = tokio::io::duplex(1 << 20);
        let a = WebSocketStream::from_raw_socket(a, Role::Client, None).await;
        let b = WebSocketStream::from_raw_socket(b, Role::Server, None).await;
        (bridge(a, ping).0, bridge(b, ping).0)
    }

    #[tokio::test]
    async fn bytes_cross_both_ways_including_large_writes() {
        let (mut a, mut b) = pair(Duration::from_secs(30)).await;
        let big: Vec<u8> = (0..300_000u32).map(|i| i as u8).collect();
        let sent = big.clone();
        let writer = tokio::spawn(async move {
            a.write_all(&sent).await.unwrap();
            let mut back = [0u8; 5];
            a.read_exact(&mut back).await.unwrap();
            back
        });
        let mut got = vec![0u8; big.len()];
        b.read_exact(&mut got).await.unwrap();
        assert_eq!(got, big);
        b.write_all(b"hello").await.unwrap();
        assert_eq!(&writer.await.unwrap(), b"hello");
    }

    #[tokio::test]
    async fn closing_one_side_reads_as_eof() {
        let (a, mut b) = pair(Duration::from_secs(30)).await;
        drop(a);
        let mut buf = [0u8; 8];
        assert_eq!(b.read(&mut buf).await.unwrap(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn silent_peer_times_out() {
        let (a, b) = tokio::io::duplex(1 << 16);
        let a = WebSocketStream::from_raw_socket(a, Role::Client, None).await;
        let (mut a, _) = bridge(a, Duration::from_secs(10));
        let _b = b; // never read: no pong ever comes back
        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(Duration::from_secs(60), a.read(&mut buf)).await.unwrap().unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn pings_keep_an_idle_link_alive() {
        let (mut a, mut b) = pair(Duration::from_secs(10)).await;
        let (mut x, mut y) = ([0u8; 8], [0u8; 8]);
        tokio::select! {
            r = a.read(&mut x) => panic!("a ended: {r:?}"),
            r = b.read(&mut y) => panic!("b ended: {r:?}"),
            _ = tokio::time::sleep(Duration::from_secs(120)) => {}
        }
    }
}
