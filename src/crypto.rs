//! Node identity and inter-node auth primitives:
//! ed25519 keypairs for identity, HMAC-based periodic tokens for requests.

use ed25519_dalek::{SigningKey, VerifyingKey};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Token validity period, seconds.
pub const TOKEN_PERIOD_SECS: u64 = 30;
/// How many periods back/forward a token is accepted (clock skew allowance).
/// Used by the auth middleware arriving in M2.1.
#[allow(dead_code)]
pub const TOKEN_WINDOW: i64 = 1;

pub struct KeyPair {
    pub secret_hex: String,
    pub public_hex: String,
}

impl KeyPair {
    pub fn generate() -> Self {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let vk: VerifyingKey = sk.verifying_key();
        KeyPair {
            secret_hex: hex::encode(sk.to_bytes()),
            public_hex: hex::encode(vk.to_bytes()),
        }
    }
}

/// `n_bytes` of CSPRNG output, hex-encoded (for network secrets etc.).
pub fn random_hex(n_bytes: usize) -> String {
    let mut buf = vec![0u8; n_bytes];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Deterministic token for a given period index.
pub fn token_at(secret: &str, period_index: u64) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(&period_index.to_be_bytes());
    let out = mac.finalize().into_bytes();
    hex::encode(&out[..16])
}

/// Token valid right now.
// Called from transport::NodeClient (dead until M2.3 wires the gossip loop into main).
#[allow(dead_code)]
pub fn token_now(secret: &str) -> String {
    token_at(secret, unix_now() / TOKEN_PERIOD_SECS)
}

/// Accept tokens from the current and neighbouring periods (±TOKEN_WINDOW).
/// Used by the auth middleware arriving in M2.1.
#[allow(dead_code)]
pub fn verify_token(secret: &str, token: &str) -> bool {
    let idx = (unix_now() / TOKEN_PERIOD_SECS) as i64;
    for delta in -TOKEN_WINDOW..=TOKEN_WINDOW {
        if token_at(secret, (idx + delta) as u64) == token {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_deterministic() {
        assert_eq!(token_at("s", 42), token_at("s", 42));
        assert_ne!(token_at("s", 42), token_at("s", 43));
        assert_ne!(token_at("s", 42), token_at("other", 42));
    }

    #[test]
    fn verify_accepts_current_and_neighbour_periods() {
        let secret = "net-secret";
        let idx = unix_now() / TOKEN_PERIOD_SECS;
        for delta in [-1i64, 0, 1] {
            assert!(verify_token(secret, &token_at(secret, (idx as i64 + delta) as u64)));
        }
    }

    #[test]
    fn verify_rejects_garbage() {
        assert!(!verify_token("net-secret", "deadbeefdeadbeefdeadbeefdeadbeef"));
        assert!(!verify_token("net-secret", ""));
    }

    #[test]
    fn keypair_is_wellformed() {
        let kp = KeyPair::generate();
        assert_eq!(kp.secret_hex.len(), 64);
        assert_eq!(kp.public_hex.len(), 64);
    }
}
