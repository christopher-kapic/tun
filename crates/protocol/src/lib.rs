//! Wire protocol shared by `cockpit-tunnel-server` and `cockpit-preview`.
//!
//! Transport: the client dials `wss://<tunnel host>/v1/connect` with
//! `Authorization: Bearer <tunnel token>`. The WebSocket is turned into a byte
//! stream ([`ws_bridge`]) and Yamux runs on top of it.
//!
//! Streams:
//! - The client opens exactly one outbound stream right after connecting: the
//!   control stream. It carries newline-delimited JSON ([`ClientMsg`] /
//!   [`ServerMsg`]). The first client message is [`ClientMsg::Hello`]; the
//!   server answers with [`ServerMsg::Welcome`].
//! - Every other stream is opened by the server, one per public HTTP request or
//!   WebSocket. The server writes a 2-byte big-endian port preamble; the client
//!   answers with one status byte ([`STREAM_OK`], [`STREAM_REFUSED`],
//!   [`STREAM_NOT_EXPOSED`]). After `STREAM_OK` the stream is a raw byte pipe
//!   to `127.0.0.1:<port>` (or `[::1]:<port>`).

pub mod mux;
pub mod ws_bridge;

use std::io;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const PROTOCOL_VERSION: u32 = 1;
pub const CONNECT_PATH: &str = "/v1/connect";

pub const ADMIN_TOKEN_PREFIX: &str = "ctadm_";
pub const TUNNEL_TOKEN_PREFIX: &str = "cttun_";
pub const ACCESS_TOKEN_PREFIX: &str = "ctacc_";
/// Long-lived per-machine API token (`cockpit-preview login`).
pub const CLIENT_TOKEN_PREFIX: &str = "ctcli_";
/// One-time enrollment code printed by `client add`; traded for a client token.
pub const ENROLL_CODE_PREFIX: &str = "ctenr_";

/// Visitor gate cookie. Parent-domain (`Domain=<preview zone>`), HttpOnly,
/// stripped before every origin request.
pub const GATE_COOKIE: &str = "__Secure-cockpit-gate";

/// Outer WebSocket ping interval. Two missed pongs drop the connection.
pub const PING_INTERVAL: Duration = Duration::from_secs(25);

/// Maximum length of one control-stream JSON line.
pub const MAX_CONTROL_LINE: usize = 64 * 1024;

pub const STREAM_OK: u8 = 0;
pub const STREAM_REFUSED: u8 = 1;
pub const STREAM_NOT_EXPOSED: u8 = 2;

/// Client process exit codes (also documented in the client README).
pub const EXIT_REVOKED: i32 = 3;
pub const EXIT_REPLACED: i32 = 4;

pub fn encode_preamble(port: u16) -> [u8; 2] {
    port.to_be_bytes()
}

pub fn decode_preamble(bytes: [u8; 2]) -> u16 {
    u16::from_be_bytes(bytes)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMsg {
    Hello { version: u32, ports: Vec<u16> },
    Expose { id: u64, port: u16 },
    Unexpose { id: u64, port: u16 },
    IceRequest { id: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMsg {
    Welcome {
        tunnel_id: String,
        /// e.g. `{port}-ab12cd3efg.previews.example.com`
        host_template: String,
        max_ports: u16,
        /// Ports the server accepted from `Hello` (may be a prefix if over `max_ports`).
        ports: Vec<u16>,
        webrtc: bool,
    },
    Reply {
        id: u64,
        ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ice: Option<IceConfig>,
    },
    Close { reason: CloseReason },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CloseReason {
    /// Tunnel deleted via the API. Terminal.
    Deleted,
    /// Tunnel TTL elapsed. Terminal.
    Expired,
    /// Another connection authenticated with the same token.
    Replaced,
    /// Server shutting down; reconnect.
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IceServer {
    pub urls: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IceConfig {
    #[serde(rename = "iceServers")]
    pub ice_servers: Vec<IceServer>,
    /// Unix seconds.
    pub expires_at: u64,
    /// TTL the credential was minted with, so consumers can refresh at 25% remaining.
    pub ttl_s: u64,
}

/// Read one newline-delimited JSON message. `Ok(None)` on clean EOF.
pub async fn read_json_line<R, T>(reader: &mut R, buf: &mut String) -> io::Result<Option<T>>
where
    R: AsyncBufRead + Unpin,
    T: DeserializeOwned,
{
    buf.clear();
    let mut limited = (&mut *reader).take(MAX_CONTROL_LINE as u64 + 1);
    let n = limited.read_line(buf).await?;
    if n == 0 {
        return Ok(None);
    }
    if n > MAX_CONTROL_LINE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "control line too long"));
    }
    serde_json::from_str(buf.trim_end())
        .map(Some)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

pub async fn write_json_line<W, T>(writer: &mut W, msg: &T) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let mut bytes = serde_json::to_vec(msg).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    writer.flush().await
}
