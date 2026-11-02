//! Stream multiplexing over the tunnel transport: Yamux (rust-yamux) behind a
//! small tokio-friendly handle.
//!
//! rust-yamux keeps reading frames for every stream regardless of whether a
//! given stream's reader is keeping up (each stream buffers at most its flow
//! control window), so one visitor who stops reading cannot stall the other
//! streams of the tunnel (audit #12). It speaks the same wire protocol as the
//! tokio-yamux implementation used before, so old and new peers interoperate.
//!
//! A driver task owns the connection. [`Control`] asks it to open streams or
//! close; [`Session::next`] yields streams the peer opened. Dropping the
//! `Session` stops the driver and closes the transport.

use std::collections::VecDeque;
use std::io;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

/// A multiplexed stream with tokio `AsyncRead`/`AsyncWrite`.
pub type Stream = Compat<yamux::Stream>;

/// Streams open at once per connection (both directions). Covers the
/// server's 512 in-progress requests, its idle origin pool, and the control
/// stream.
pub const MAX_STREAMS: usize = 600;
/// Inbound streams waiting to be picked up by `Session::next`.
const INBOUND_BACKLOG: usize = 256;

fn config() -> yamux::Config {
    let mut cfg = yamux::Config::default();
    // Each stream may buffer up to the spec's 256 KiB window; no auto-tuning
    // beyond that, so a peer cannot grow buffers past this bound.
    cfg.set_max_connection_receive_window(Some(MAX_STREAMS * yamux::DEFAULT_CREDIT as usize));
    cfg.set_max_num_streams(MAX_STREAMS);
    cfg
}

enum Cmd {
    Open(oneshot::Sender<io::Result<Stream>>),
    Close(oneshot::Sender<()>),
}

/// Cheap to clone; every clone talks to the same driver.
#[derive(Clone)]
pub struct Control {
    tx: mpsc::Sender<Cmd>,
}

impl Control {
    pub async fn open_stream(&mut self) -> io::Result<Stream> {
        let (tx, rx) = oneshot::channel();
        self.tx.send(Cmd::Open(tx)).await.map_err(|_| io::Error::from(io::ErrorKind::NotConnected))?;
        rx.await.map_err(|_| io::Error::from(io::ErrorKind::NotConnected))?
    }

    /// Close the connection gracefully (GoAway) and stop the driver.
    pub async fn close(&mut self) {
        let (tx, rx) = oneshot::channel();
        if self.tx.send(Cmd::Close(tx)).await.is_ok() {
            let _ = rx.await;
        }
    }
}

pub struct Session {
    control: Control,
    inbound: mpsc::Receiver<Stream>,
    driver: JoinHandle<()>,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

impl Session {
    pub fn new_client<T>(io: T) -> Self
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self::new(io, yamux::Mode::Client)
    }

    pub fn new_server<T>(io: T) -> Self
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self::new(io, yamux::Mode::Server)
    }

    fn new<T>(io: T, mode: yamux::Mode) -> Self
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let conn = yamux::Connection::new(io.compat(), config(), mode);
        let (cmd_tx, cmd_rx) = mpsc::channel(64);
        let (in_tx, in_rx) = mpsc::channel(INBOUND_BACKLOG);
        let driver = tokio::spawn(drive(conn, cmd_rx, in_tx));
        Self { control: Control { tx: cmd_tx }, inbound: in_rx, driver }
    }

    pub fn control(&self) -> Control {
        self.control.clone()
    }

    /// The next stream the peer opened; `None` once the connection ended.
    pub async fn next(&mut self) -> Option<Stream> {
        self.inbound.recv().await
    }
}

async fn drive<T>(mut conn: yamux::Connection<T>, mut cmds: mpsc::Receiver<Cmd>, inbound: mpsc::Sender<Stream>)
where
    T: futures_util::AsyncRead + futures_util::AsyncWrite + Unpin,
{
    let mut opening: VecDeque<oneshot::Sender<io::Result<Stream>>> = VecDeque::new();
    let mut closing: Option<oneshot::Sender<()>> = None;
    let mut cmds_done = false;
    std::future::poll_fn(|cx| step(cx, &mut conn, &mut cmds, &mut cmds_done, &inbound, &mut opening, &mut closing)).await;
    if let Some(done) = closing {
        let _ = done.send(());
    }
}

fn step<T>(
    cx: &mut Context<'_>,
    conn: &mut yamux::Connection<T>,
    cmds: &mut mpsc::Receiver<Cmd>,
    cmds_done: &mut bool,
    inbound: &mpsc::Sender<Stream>,
    opening: &mut VecDeque<oneshot::Sender<io::Result<Stream>>>,
    closing: &mut Option<oneshot::Sender<()>>,
) -> Poll<()>
where
    T: futures_util::AsyncRead + futures_util::AsyncWrite + Unpin,
{
    loop {
        if closing.is_some() {
            return conn.poll_close(cx).map(|_| ());
        }
        let mut progress = false;

        while !*cmds_done {
            let Poll::Ready(cmd) = cmds.poll_recv(cx) else { break };
            match cmd {
                Some(Cmd::Open(reply)) => opening.push_back(reply),
                Some(Cmd::Close(done)) => {
                    *closing = Some(done);
                    break;
                }
                // Every Control is gone: nobody can open streams any more,
                // but inbound streams and open ones keep working.
                None => *cmds_done = true,
            }
        }
        if closing.is_some() {
            continue;
        }

        if !opening.is_empty() {
            if let Poll::Ready(result) = conn.poll_new_outbound(cx) {
                let reply = opening.pop_front().expect("checked non-empty");
                let failed = result.is_err();
                let _ = reply.send(result.map(FuturesAsyncReadCompatExt::compat).map_err(io::Error::other));
                if failed {
                    for r in opening.drain(..) {
                        let _ = r.send(Err(io::ErrorKind::NotConnected.into()));
                    }
                    return Poll::Ready(());
                }
                progress = true;
            }
        }

        // Always polled: this is what reads frames for every stream.
        match conn.poll_next_inbound(cx) {
            Poll::Ready(Some(Ok(stream))) => {
                // A full backlog drops (resets) the stream rather than block the connection.
                let _ = inbound.try_send(stream.compat());
                progress = true;
            }
            Poll::Ready(Some(Err(e))) => {
                tracing::debug!(error = %e, "yamux connection error");
                return Poll::Ready(());
            }
            Poll::Ready(None) => return Poll::Ready(()),
            Poll::Pending => {}
        }

        if !progress {
            return Poll::Pending;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn pair() -> (Session, Session) {
        let (a, b) = tokio::io::duplex(1 << 20);
        (Session::new_client(a), Session::new_server(b))
    }

    #[tokio::test]
    async fn open_echo_and_close() {
        let (client, mut server) = pair();
        tokio::spawn(async move {
            while let Some(mut s) = server.next().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 300_000];
                    s.read_exact(&mut buf).await.unwrap();
                    s.write_all(&buf).await.unwrap();
                    s.flush().await.unwrap();
                });
            }
        });
        let mut ctl = client.control();
        let s = ctl.open_stream().await.unwrap();
        let (mut rd, mut wr) = tokio::io::split(s);
        let data: Vec<u8> = (0..300_000u32).map(|i| i as u8).collect();
        let sent = data.clone();
        let w = tokio::spawn(async move {
            wr.write_all(&sent).await.unwrap();
            wr.flush().await.unwrap();
            wr
        });
        let mut back = vec![0u8; data.len()];
        rd.read_exact(&mut back).await.unwrap();
        assert_eq!(back, data);
        drop(w.await);
        tokio::time::timeout(Duration::from_secs(2), ctl.close()).await.unwrap();
        assert!(ctl.open_stream().await.is_err());
    }

    #[tokio::test]
    async fn dropping_the_session_ends_the_peer() {
        let (client, mut server) = pair();
        drop(client);
        assert!(tokio::time::timeout(Duration::from_secs(2), server.next()).await.unwrap().is_none());
    }

    /// Interop with the tokio-yamux implementation older peers run.
    #[tokio::test]
    async fn talks_to_tokio_yamux() {
        use futures_util::StreamExt;
        let (a, b) = tokio::io::duplex(1 << 20);
        // The configuration clients before the rust-yamux switch used.
        let old_cfg = tokio_yamux::Config { max_stream_window_size: 256 * 1024, enable_keepalive: false, ..Default::default() };
        let mut old = tokio_yamux::Session::new_client(a, old_cfg);
        let mut old_ctl = old.control();
        tokio::spawn(async move { while old.next().await.is_some() {} });
        let mut new = Session::new_server(b);
        tokio::spawn(async move {
            while let Some(mut s) = new.next().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4];
                    s.read_exact(&mut buf).await.unwrap();
                    s.write_all(&buf).await.unwrap();
                    s.flush().await.unwrap();
                });
            }
        });
        let mut s = old_ctl.open_stream().await.unwrap();
        s.write_all(b"ping").await.unwrap();
        s.flush().await.unwrap();
        let mut buf = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(2), s.read_exact(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf, b"ping");
    }
}
