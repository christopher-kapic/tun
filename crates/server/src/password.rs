//! Tunnel passwords: argon2id (PHC strings), hashed and verified off the async
//! runtime because each takes tens of milliseconds by design.

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use std::sync::LazyLock;
use std::time::Duration;

use argon2::Argon2;
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;

pub const MIN_PASSWORD_LEN: usize = 8;
pub const MAX_PASSWORD_LEN: usize = 256;
pub const MAX_USERNAME_LEN: usize = 64;

/// Argon2 runs at most this many at once (each takes ~19 MiB and tens of ms).
const MAX_CONCURRENT: usize = 2;
/// A caller waits this long for a slot, then gives up (`Busy`), so a flood
/// cannot queue unbounded work.
const SLOT_WAIT: Duration = Duration::from_secs(3);
static SLOTS: LazyLock<Semaphore> = LazyLock::new(|| Semaphore::new(MAX_CONCURRENT));

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Match,
    NoMatch,
    /// Too many password checks are already running.
    Busy,
}

pub async fn hash(password: String) -> anyhow::Result<String> {
    let _slot = tokio::time::timeout(SLOT_WAIT, SLOTS.acquire())
        .await
        .map_err(|_| anyhow::anyhow!("password hashing is busy; try again"))??;
    tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| anyhow::anyhow!("hashing password: {e}"))
    })
    .await?
}

/// True if `username` matches and `password` verifies against `phc`. The
/// password is always checked, so a wrong username takes as long as a wrong password.
pub async fn verify(expected_user: String, phc: String, username: String, password: String) -> Verdict {
    let Ok(Ok(_slot)) = tokio::time::timeout(SLOT_WAIT, SLOTS.acquire()).await else {
        return Verdict::Busy;
    };
    let ok = tokio::task::spawn_blocking(move || {
        let user_ok: bool = expected_user.as_bytes().ct_eq(username.as_bytes()).into();
        let pass_ok = PasswordHash::new(&phc)
            .map(|parsed| Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
            .unwrap_or(false);
        user_ok && pass_ok
    })
    .await
    .unwrap_or(false);
    if ok {
        Verdict::Match
    } else {
        Verdict::NoMatch
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn hash_and_verify() {
        let phc = super::hash("correct horse".into()).await.unwrap();
        assert!(phc.starts_with("$argon2id$"));
        use super::Verdict::*;
        assert_eq!(super::verify("ann".into(), phc.clone(), "ann".into(), "correct horse".into()).await, Match);
        assert_eq!(super::verify("ann".into(), phc.clone(), "bob".into(), "correct horse".into()).await, NoMatch);
        assert_eq!(super::verify("ann".into(), phc.clone(), "ann".into(), "wrong".into()).await, NoMatch);
        assert_eq!(super::verify("ann".into(), "not a hash".into(), "ann".into(), "x".into()).await, NoMatch);
    }
}
