//! Does one stream whose reader stops reading stall the others? (audit #12)

use std::time::Duration;

use cockpit_tunnel_protocol::mux::Session;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn unread_stream_does_not_stall_others() {
    let (a, b) = tokio::io::duplex(1 << 20);
    let mut client = Session::new_client(a);
    let mut client_ctl = client.control();
    tokio::spawn(async move { while client.next().await.is_some() {} });

    // Server: every accepted stream writes 64 small chunks, then echoes.
    let mut server = Session::new_server(b);
    tokio::spawn(async move {
        while let Some(mut s) = server.next().await {
            tokio::spawn(async move {
                let mut first = [0u8; 1];
                if s.read_exact(&mut first).await.is_err() {
                    return;
                }
                if first[0] == b'F' {
                    for _ in 0..64 {
                        if s.write_all(&[b'x'; 100]).await.is_err() {
                            return;
                        }
                        let _ = s.flush().await;
                        tokio::task::yield_now().await;
                    }
                } else {
                    let _ = s.write_all(b"pong").await;
                    let _ = s.flush().await;
                }
                tokio::time::sleep(Duration::from_secs(30)).await;
            });
        }
    });

    // Stream 1 asks for a flood, then is never read.
    let mut flood = client_ctl.open_stream().await.unwrap();
    flood.write_all(b"F").await.unwrap();
    flood.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Stream 2 must still work.
    let mut other = client_ctl.open_stream().await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(3), async {
        other.write_all(b"P").await?;
        other.flush().await?;
        let mut buf = [0u8; 4];
        other.read_exact(&mut buf).await?;
        Ok::<_, std::io::Error>(buf)
    })
    .await;
    drop(flood);
    assert!(matches!(result, Ok(Ok(b)) if &b == b"pong"), "second stream stalled: {result:?}");
}
