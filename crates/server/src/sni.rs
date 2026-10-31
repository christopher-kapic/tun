//! Read the SNI from a TLS ClientHello without consuming it, so the connection
//! can be spliced to coturn untouched or handed to rustls.

use std::io;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::Instant;

/// Largest TLS plaintext record (2^14) plus the 5-byte header.
const MAX_PEEK: usize = 5 + 16_384;
const RETRY_DELAY: Duration = Duration::from_millis(5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SniPeek {
    /// Lowercased host name, trailing dot removed.
    Sni(String),
    /// A ClientHello without a host_name server_name entry.
    NoSni,
    /// Not a TLS handshake (or a malformed one).
    NotTls,
}

/// Peek until the first TLS record is complete, then parse its ClientHello.
/// Consumes nothing. Errors with `TimedOut` if the record does not arrive
/// within `timeout`, `UnexpectedEof` if the peer closes first.
pub async fn peek_sni(tcp: &TcpStream, timeout: Duration) -> io::Result<SniPeek> {
    let deadline = Instant::now() + timeout;
    let mut buf = vec![0u8; MAX_PEEK];
    loop {
        let n = match tokio::time::timeout_at(deadline, tcp.peek(&mut buf)).await {
            Ok(res) => res?,
            Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "timed out waiting for ClientHello")),
        };
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "closed before ClientHello"));
        }
        if let Some(result) = parse(&buf[..n]) {
            return Ok(result);
        }
        // peek returns whatever is buffered, immediately; wait for more to arrive.
        if Instant::now() + RETRY_DELAY >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "timed out waiting for ClientHello"));
        }
        tokio::time::sleep(RETRY_DELAY).await;
    }
}

/// `None` = need more bytes. Only the first record is inspected: a ClientHello
/// split across records (rare; very large hellos, e.g. post-quantum key shares)
/// whose server_name lies beyond the first record is reported as `NoSni`.
fn parse(buf: &[u8]) -> Option<SniPeek> {
    if buf[0] != 0x16 {
        return Some(SniPeek::NotTls);
    }
    if buf.len() >= 2 && buf[1] != 0x03 {
        return Some(SniPeek::NotTls);
    }
    if buf.len() < 5 {
        return None;
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if record_len == 0 || record_len > MAX_PEEK - 5 {
        return Some(SniPeek::NotTls);
    }
    if buf.len() < 5 + record_len {
        return None;
    }
    Some(parse_handshake(&buf[5..5 + record_len]))
}

fn parse_handshake(record: &[u8]) -> SniPeek {
    let mut r = Reader(record);
    match r.u8() {
        Some(1) => {}
        _ => return SniPeek::NotTls,
    }
    let Some(hs_len) = r.u24() else {
        return SniPeek::NotTls;
    };
    let truncated = hs_len > r.0.len();
    let body = &r.0[..hs_len.min(r.0.len())];
    match parse_client_hello(body) {
        Ok(peek) => peek,
        Err(()) if truncated => SniPeek::NoSni,
        Err(()) => SniPeek::NotTls,
    }
}

fn parse_client_hello(body: &[u8]) -> Result<SniPeek, ()> {
    let mut r = Reader(body);
    r.skip(2)?; // legacy_version
    r.skip(32)?; // random
    let sid = r.u8().ok_or(())? as usize;
    r.skip(sid)?;
    let suites = r.u16().ok_or(())? as usize;
    r.skip(suites)?;
    let compression = r.u8().ok_or(())? as usize;
    r.skip(compression)?;
    if r.0.is_empty() {
        return Ok(SniPeek::NoSni);
    }
    let ext_len = r.u16().ok_or(())? as usize;
    let mut exts = Reader(r.take(ext_len)?);
    while !exts.0.is_empty() {
        let ext_type = exts.u16().ok_or(())?;
        let len = exts.u16().ok_or(())? as usize;
        let data = exts.take(len)?;
        if ext_type == 0 {
            return parse_server_name(data);
        }
    }
    Ok(SniPeek::NoSni)
}

fn parse_server_name(data: &[u8]) -> Result<SniPeek, ()> {
    let mut r = Reader(data);
    let list_len = r.u16().ok_or(())? as usize;
    let mut list = Reader(r.take(list_len)?);
    while !list.0.is_empty() {
        let name_type = list.u8().ok_or(())?;
        let len = list.u16().ok_or(())? as usize;
        let name = list.take(len)?;
        if name_type == 0 {
            let name = std::str::from_utf8(name).map_err(|_| ())?;
            if name.is_empty() || !name.is_ascii() {
                return Err(());
            }
            return Ok(SniPeek::Sni(name.trim_end_matches('.').to_ascii_lowercase()));
        }
    }
    Ok(SniPeek::NoSni)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ()> {
        if self.0.len() < n {
            return Err(());
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn skip(&mut self, n: usize) -> Result<(), ()> {
        self.take(n).map(|_| ())
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).ok().map(|b| b[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2).ok().map(|b| u16::from_be_bytes([b[0], b[1]]))
    }

    fn u24(&mut self) -> Option<usize> {
        self.take(3).ok().map(|b| ((b[0] as usize) << 16) | ((b[1] as usize) << 8) | b[2] as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_hello(sni: Option<&str>) -> Vec<u8> {
        let mut exts = Vec::new();
        if let Some(name) = sni {
            let mut entry = vec![0u8];
            entry.extend_from_slice(&(name.len() as u16).to_be_bytes());
            entry.extend_from_slice(name.as_bytes());
            let mut data = (entry.len() as u16).to_be_bytes().to_vec();
            data.extend_from_slice(&entry);
            exts.extend_from_slice(&0u16.to_be_bytes());
            exts.extend_from_slice(&(data.len() as u16).to_be_bytes());
            exts.extend_from_slice(&data);
        }
        // An unrelated extension (supported_versions) before/after SNI doesn't matter.
        exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);

        let mut hello = vec![0x03, 0x03];
        hello.extend_from_slice(&[7u8; 32]);
        hello.push(0); // session id
        hello.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // one suite
        hello.extend_from_slice(&[0x01, 0x00]); // null compression
        hello.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        hello.extend_from_slice(&exts);

        let mut hs = vec![1u8];
        hs.extend_from_slice(&(hello.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&hello);

        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn extracts_sni() {
        let rec = client_hello(Some("Turn.Example.com."));
        assert_eq!(parse(&rec), Some(SniPeek::Sni("turn.example.com".into())));
    }

    #[test]
    fn no_sni() {
        assert_eq!(parse(&client_hello(None)), Some(SniPeek::NoSni));
    }

    #[test]
    fn incomplete_needs_more() {
        let rec = client_hello(Some("turn.example.com"));
        for cut in 1..rec.len() {
            assert_eq!(parse(&rec[..cut]), None, "cut at {cut}");
        }
    }

    #[test]
    fn not_tls() {
        assert_eq!(parse(b"GET / HTTP/1.1\r\n"), Some(SniPeek::NotTls));
        assert_eq!(parse(&[0x16, 0x01]), Some(SniPeek::NotTls));
    }

    #[test]
    fn real_rustls_client_hello() {
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let name = rustls::pki_types::ServerName::try_from("turn.example.com").unwrap();
        let mut conn = rustls::ClientConnection::new(std::sync::Arc::new(config), name).unwrap();
        let mut out = Vec::new();
        conn.write_tls(&mut out).unwrap();
        assert_eq!(parse(&out), Some(SniPeek::Sni("turn.example.com".into())));
    }

    #[tokio::test]
    async fn peek_does_not_consume() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let rec = client_hello(Some("api.example.com"));
        let sent = rec.clone();
        let client = tokio::spawn(async move {
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            // Split the write to exercise the retry loop.
            s.write_all(&sent[..10]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            s.write_all(&sent[10..]).await.unwrap();
            s
        });
        let (mut server, _) = listener.accept().await.unwrap();
        let peek = peek_sni(&server, Duration::from_secs(5)).await.unwrap();
        assert_eq!(peek, SniPeek::Sni("api.example.com".into()));
        let mut got = vec![0u8; rec.len()];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(got, rec);
        drop(client.await.unwrap());
    }
}
