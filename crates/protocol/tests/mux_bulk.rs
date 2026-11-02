//! Bulk throughput through ws_bridge + mux, both ends in-process. Run with
//! `cargo test --release -p cockpit-tunnel-protocol --test mux_bulk -- --ignored --nocapture`.

use std::time::{Duration, Instant};

use cockpit_tunnel_protocol::{mux::Session, ws_bridge};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::WebSocketStream;

/// utime + stime of this process (Linux clock ticks are 10 ms).
fn cpu() -> Duration {
    let ticks = std::fs::read_to_string("/proc/self/stat")
        .ok()
        .and_then(|s| {
            let f: Vec<u64> = s.rsplit(") ").next()?.split(' ').skip(11).take(2).filter_map(|x| x.parse().ok()).collect();
            Some(f.iter().sum::<u64>())
        })
        .unwrap_or(0);
    Duration::from_millis(ticks * 10)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn bulk() {
    let (a, b) = tokio::io::duplex(256 * 1024);
    let a = WebSocketStream::from_raw_socket(a, Role::Client, None).await;
    let b = WebSocketStream::from_raw_socket(b, Role::Server, None).await;
    let (da, _ja) = ws_bridge::bridge(a, Duration::from_secs(25));
    let (db, _jb) = ws_bridge::bridge(b, Duration::from_secs(25));
    let client = Session::new_client(da);
    let mut server = Session::new_server(db);
    const TOTAL: usize = 4 << 30;
    tokio::spawn(async move {
        while let Some(mut s) = server.next().await {
            tokio::spawn(async move {
                let mut go = [0u8; 1];
                s.read_exact(&mut go).await.unwrap();
                let chunk = vec![7u8; 64 * 1024];
                let mut sent = 0;
                while sent < TOTAL / 8 {
                    s.write_all(&chunk).await.unwrap();
                    sent += chunk.len();
                }
                s.shutdown().await.unwrap();
            });
        }
    });
    let (c0, t0) = (cpu(), Instant::now());
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let mut ctl = client.control();
        tasks.push(tokio::spawn(async move {
            let mut s = ctl.open_stream().await.unwrap();
            s.write_all(b"g").await.unwrap();
            s.flush().await.unwrap();
            let mut buf = vec![0u8; 64 * 1024];
            let mut got = 0;
            loop {
                let n = s.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                got += n;
            }
            got
        }));
    }
    let mut total = 0;
    for t in tasks {
        total += t.await.unwrap();
    }
    let (cpu_s, wall) = ((cpu() - c0).as_secs_f64(), t0.elapsed().as_secs_f64());
    println!("bulk: {} MiB in {:.2}s wall, {:.2}s CPU → {:.0} MiB per CPU-s", total >> 20, wall, cpu_s, (total >> 20) as f64 / cpu_s);
}

