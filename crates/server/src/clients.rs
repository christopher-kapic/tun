//! Client enrollment shared by the `client` subcommands and the admin API.

use cockpit_tunnel_protocol::ENROLL_CODE_PREFIX;

use crate::config::Config;
use crate::db::Db;
use crate::tokens::{self, now};

/// How long a `client add` login code works.
pub const ENROLL_TTL_S: i64 = 15 * 60;
pub const MAX_NAME_LEN: usize = 64;

pub struct Enrollment {
    pub name: String,
    pub login_command: String,
    pub expires_at: i64,
}

pub enum AddError {
    Invalid(String),
    Taken,
    Other(anyhow::Error),
}

impl From<anyhow::Error> for AddError {
    fn from(e: anyhow::Error) -> Self {
        Self::Other(e)
    }
}

pub fn validate_name(name: &str) -> Result<(), String> {
    let ok = !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(format!("client name must be 1..={MAX_NAME_LEN} characters: letters, digits, '.', '_', '-'"))
    }
}

/// Create client `name` and its one-time login command.
pub async fn add(db: &Db, cfg: &Config, name: &str) -> Result<Enrollment, AddError> {
    validate_name(name).map_err(AddError::Invalid)?;
    let code = tokens::random_token(ENROLL_CODE_PREFIX);
    let expires_at = now() + ENROLL_TTL_S;
    let id = format!("cl{}", tokens::random_tunnel_id());
    match db.create_client(id, name.to_string(), tokens::hash_token(&code), expires_at).await? {
        Some(_) => Ok(Enrollment {
            name: name.to_string(),
            login_command: format!("cockpit-preview login '{code}@{}'", cfg.api_host),
            expires_at,
        }),
        None => Err(AddError::Taken),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn names() {
        assert!(super::validate_name("laptop").is_ok());
        assert!(super::validate_name("ci.runner-2_a").is_ok());
        for bad in ["", "has space", "slash/x", "ünï", &"x".repeat(65)] {
            assert!(super::validate_name(bad).is_err(), "{bad}");
        }
    }
}
