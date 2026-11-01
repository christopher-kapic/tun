//! Turn a WebSocket into a plain byte stream for Yamux.
//!
//! [`WsIo`] implements `AsyncRead`/`AsyncWrite` directly on the WebSocket, so
//! Yamux's framed writer hands its buffered frames straight to the WebSocket
//! (one binary message per write, flushed when Yamux flushes) and reads
//! consume binary messages in place. There is no pump task and no extra copy
//! through an in-memory pipe, and the two directions never wait on each other.
//!
//! Keepalive: a ping every `ping_interval`; the stream fails after ~2.5
//! intervals without hearing anything from the peer (any frame counts, so a
//! busy link is never declared dead because its pong is queued behind data).
//! Text frames are ignored. No nested RFC 6455: only bytes cross this pipe.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use std::time::Duration;

use bytes::{Buf, Bytes};
use futures_util::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Interval, MissedTickBehavior};
use tokio_tungstenite::tungstenite::{self, Message};
use tokio_tungstenite::WebSocketStream;

/// Largest single WebSocket message written (well under the 512 KiB frame cap).
const MAX_MESSAGE: usize = 64 * 1024;

pub struct WsIo<S> {
    ws: WebSocketStream<S>,
    /// Unread part of the last binary message.
    rbuf: Bytes,
    ticker: Interval,
    last_heard: Instant,
    dead_after: Duration,
    ping_due: bool,
}

pub fn ws_io<S>(ws: WebSocketStream<S>, ping_interval: Duration) -> WsIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut ticker = tokio::time::interval_at(Instant::now() + ping_interval, ping_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    WsIo {
        ws,
        rbuf: Bytes::new(),
        ticker,
        last_heard: Instant::now(),
        dead_after: ping_interval * 2 + ping_interval / 2,
        ping_due: false,
    }
}

fn to_io(e: tungstenite::Error) -> io::Error {
    match e {
        tungstenite::Error::Io(e) => e,
        tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed => io::ErrorKind::BrokenPipe.into(),
        e => io::Error::other(e),
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> WsIo<S> {
    fn ws(&mut self) -> Pin<&mut WebSocketStream<S>> {
        Pin::new(&mut self.ws)
    }

    /// Timer-driven keepalive, run from `poll_read` (which Yamux polls whenever
    /// its session is polled). Registers the timer waker as a side effect.
    fn poll_keepalive(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        while self.ticker.poll_tick(cx).is_ready() {
            if self.last_heard.elapsed() > self.dead_after {
                tracing::debug!("websocket keepalive timeout");
                return Err(io::ErrorKind::TimedOut.into());
            }
            self.ping_due = true;
        }
        if self.ping_due {
            if let Poll::Ready(r) = self.ws().poll_ready(cx) {
                r.map_err(to_io)?;
                self.ws().start_send(Message::Ping(Bytes::new())).map_err(to_io)?;
                self.ping_due = false;
                // Pending is fine: Yamux flushes on every session poll.
                if let Poll::Ready(r) = self.ws().poll_flush(cx) {
                    r.map_err(to_io)?;
                }
            }
        }
        Ok(())
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsIo<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.poll_keepalive(cx)?;
        loop {
            if !this.rbuf.is_empty() {
                let n = this.rbuf.len().min(buf.remaining());
                buf.put_slice(&this.rbuf[..n]);
                this.rbuf.advance(n);
                return Poll::Ready(Ok(()));
            }
            match ready!(this.ws().poll_next(cx)) {
                Some(Ok(msg)) => {
                    this.last_heard = Instant::now();
                    match msg {
                        Message::Binary(data) => this.rbuf = data,
                        Message::Close(_) => return Poll::Ready(Ok(())),
                        // Pings are answered by tungstenite on the next flush.
                        _ => {}
                    }
                }
                Some(Err(e)) => return Poll::Ready(Err(to_io(e))),
                None => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WsIo<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(this.ws().poll_ready(cx)).map_err(to_io)?;
        let n = data.len().min(MAX_MESSAGE);
        this.ws().start_send(Message::Binary(Bytes::copy_from_slice(&data[..n]))).map_err(to_io)?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().ws().poll_flush(cx).map_err(to_io)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match ready!(self.get_mut().ws().poll_close(cx)) {
            Ok(()) | Err(tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed) => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(to_io(e))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_tungstenite::tungstenite::protocol::Role;

    async fn pair(ping: Duration) -> (WsIo<tokio::io::DuplexStream>, WsIo<tokio::io::DuplexStream>) {
        let (a, b) = tokio::io::duplex(1 << 20);
        let a = WebSocketStream::from_raw_socket(a, Role::Client, None).await;
        let b = WebSocketStream::from_raw_socket(b, Role::Server, None).await;
        (ws_io(a, ping), ws_io(b, ping))
    }

    #[tokio::test]
    async fn bytes_cross_both_ways_including_large_writes() {
        let (mut a, mut b) = pair(Duration::from_secs(30)).await;
        let big: Vec<u8> = (0..300_000u32).map(|i| i as u8).collect();
        let sent = big.clone();
        let writer = tokio::spawn(async move {
            a.write_all(&sent).await.unwrap();
            a.flush().await.unwrap();
            let mut back = [0u8; 5];
            a.read_exact(&mut back).await.unwrap();
            back
        });
        let mut got = vec![0u8; big.len()];
        b.read_exact(&mut got).await.unwrap();
        assert_eq!(got, big);
        b.write_all(b"hello").await.unwrap();
        b.flush().await.unwrap();
        assert_eq!(&writer.await.unwrap(), b"hello");
    }

    #[tokio::test]
    async fn close_reads_as_eof() {
        let (mut a, mut b) = pair(Duration::from_secs(30)).await;
        a.shutdown().await.unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(b.read(&mut buf).await.unwrap(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn silent_peer_times_out() {
        let (a, b) = tokio::io::duplex(1 << 16);
        let a = WebSocketStream::from_raw_socket(a, Role::Client, None).await;
        let mut a = ws_io(a, Duration::from_secs(10));
        // `b` is never read, so no pong ever comes back.
        let _b = b;
        let mut buf = [0u8; 8];
        let err = tokio::time::timeout(Duration::from_secs(60), a.read(&mut buf)).await.unwrap().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test(start_paused = true)]
    async fn pings_keep_an_idle_link_alive() {
        let (mut a, mut b) = pair(Duration::from_secs(10)).await;
        let mut buf = [0u8; 8];
        let both = async {
            tokio::select! {
                r = a.read(&mut buf) => panic!("a ended: {r:?}"),
                r = async { let mut x = [0u8; 8]; b.read(&mut x).await } => panic!("b ended: {r:?}"),
                _ = tokio::time::sleep(Duration::from_secs(120)) => {}
            }
        };
        both.await;
    }
}
