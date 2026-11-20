//! HTTP basic authentication against bcrypt hashes, as the Prometheus exporter-toolkit does.

use std::{
    collections::HashMap,
    io,
    sync::{Arc, Mutex},
};

use aws_lc_rs::digest::{SHA256, digest};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hyper::header::HeaderValue;

// exporter-toolkit v0.20.0 web/cache.go: at most this many verified results are remembered.
const CACHE_SIZE: usize = 100;
// exporter-toolkit v0.20.0 web/handler.go: hash of "fakepassword", checked for unknown users so
// that response time does not reveal which users exist.
const FAKE_HASH: &str = "$2y$10$QOauhQNbBCuQDKes6eFzPeMqBSjb7Mr5DUmpZ/VcEd00UAV/LDeSi";

/// Users and bcrypt hashes that a request must match.
pub struct BasicAuth {
    users: HashMap<String, String>,
    /// SHA-256 of (user, hash, password) to the bcrypt verdict, so repeated scrapes skip bcrypt.
    cache: Mutex<HashMap<[u8; 32], bool>>,
    /// Only one bcrypt runs at a time: it is CPU intensive and must not starve other work.
    serial: Arc<tokio::sync::Mutex<()>>,
}

impl BasicAuth {
    /// Fail when any hash is not a bcrypt hash.
    pub fn new(users: impl IntoIterator<Item = (String, String)>) -> io::Result<Self> {
        let users: HashMap<_, _> = users.into_iter().collect();
        for (user, hash) in &users {
            // exporter-toolkit v0.20.0 web/handler.go validateUsers: bcrypt.Cost must parse every hash.
            hash.parse::<bcrypt::HashParts>().map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid bcrypt hash for user {user:?}: {error}"),
                )
            })?;
        }
        Ok(Self {
            users,
            cache: Mutex::new(HashMap::new()),
            serial: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    /// Whether `authorization` carries a known user and the password that matches its hash.
    pub async fn permits(&self, authorization: Option<&HeaderValue>) -> bool {
        // RFC 7617 §2: the credentials are `user-id ":" password`, base64-encoded after "Basic".
        let Some((user, password)) = authorization.and_then(|value| credentials(value.as_bytes()))
        else {
            return false;
        };
        let stored = self.users.get(&user);
        let hash = stored.map_or(FAKE_HASH, String::as_str);
        let key = cache_key(&user, hash, &password);
        let cached = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&key)
            .copied();
        let verified = match cached {
            Some(verified) => verified,
            None => {
                let serial = Arc::clone(&self.serial).lock_owned().await;
                let hash = hash.to_owned();
                let verified = tokio::task::spawn_blocking(move || {
                    // The guard moves in so a cancelled request cannot free it while bcrypt still runs.
                    let _serial = serial;
                    // Go's bcrypt rejects passwords over 72 bytes instead of truncating them.
                    bcrypt::non_truncating_verify(password, &hash).unwrap_or(false)
                })
                .await
                .unwrap_or(false);
                let mut cache = self
                    .cache
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if cache.len() >= CACHE_SIZE
                    && let Some(victim) = cache.keys().next().copied()
                {
                    cache.remove(&victim);
                }
                cache.insert(key, verified);
                verified
            }
        };
        // An unknown user never passes, even with the password of the fake hash.
        verified && stored.is_some()
    }
}

// Go net/http Request.BasicAuth: a case-insensitive "Basic" scheme and standard base64.
fn credentials(value: &[u8]) -> Option<(String, Vec<u8>)> {
    const SCHEME: &[u8] = b"Basic ";
    let encoded = value
        .get(..SCHEME.len())
        .filter(|prefix| prefix.eq_ignore_ascii_case(SCHEME))
        .map(|_| &value[SCHEME.len()..])?;
    let decoded = STANDARD.decode(encoded).ok()?;
    let split = decoded.iter().position(|byte| *byte == b':')?;
    let user = String::from_utf8(decoded[..split].to_vec()).ok()?;
    Some((user, decoded[split + 1..].to_vec()))
}

fn cache_key(user: &str, hash: &str, password: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(user.len() + hash.len() + password.len() + 24);
    for field in [user.as_bytes(), hash.as_bytes(), password] {
        input.extend_from_slice(&(field.len() as u64).to_be_bytes());
        input.extend_from_slice(field);
    }
    let mut key = [0; 32];
    key.copy_from_slice(digest(&SHA256, &input).as_ref());
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    // exporter-toolkit v0.20.0 web/testdata/web_config_users.good.yml: bcrypt cost 10 hashes.
    const DAVE: &str = "$2y$10$2UXri9cIDdgeKjBo4Rlpx.U3ZLDV8X1IxKmsfOvhcM5oXQt/mLmXq";
    const CAROL: &str = "$2y$10$qRTBuFoULoYNA7AQ/F3ck.trZBPyjV64.oA4ZsSBCIWvXuvQlQTuu";
    // `htpasswd -nbBC 4 u pw`: cost 4 keeps debug builds fast.
    const CHEAP: &str = "$2y$04$rMNoGfh5s9sLzpV90fV9N.Q46UW8WIePlvnCWQkK2mshf8l00ODMu";

    fn cheap() -> BasicAuth {
        BasicAuth::new([("u".to_owned(), CHEAP.to_owned())]).unwrap()
    }

    fn header(user: &str, password: &str) -> HeaderValue {
        let encoded = STANDARD.encode(format!("{user}:{password}"));
        HeaderValue::from_str(&format!("Basic {encoded}")).unwrap()
    }

    #[tokio::test]
    async fn permits_known_users_with_their_exporter_toolkit_hashes() {
        let auth = BasicAuth::new([
            ("dave".to_owned(), DAVE.to_owned()),
            ("carol".to_owned(), CAROL.to_owned()),
        ])
        .unwrap();
        assert!(auth.permits(Some(&header("dave", "dave123"))).await);
        assert!(auth.permits(Some(&header("carol", "carol123"))).await);
        assert!(!auth.permits(Some(&header("dave", "carol123"))).await);
    }

    #[tokio::test]
    async fn rejects_wrong_password_and_unknown_user() {
        let auth = cheap();
        assert!(auth.permits(Some(&header("u", "pw"))).await);
        assert!(!auth.permits(Some(&header("u", "bad"))).await);
        assert!(!auth.permits(Some(&header("nonexistent", "pw"))).await);
    }

    #[tokio::test]
    async fn unknown_user_never_passes_with_the_fake_hash_password() {
        let auth = cheap();
        assert!(
            !auth
                .permits(Some(&header("nonexistent", "fakepassword")))
                .await
        );
        // The verdict for the fake hash is cached: ask again.
        assert!(
            !auth
                .permits(Some(&header("nonexistent", "fakepassword")))
                .await
        );
    }

    #[tokio::test]
    async fn rejects_missing_or_malformed_credentials() {
        let auth = cheap();
        assert!(!auth.permits(None).await);
        for value in [
            "Bearer abc",
            "Basic",
            "Basic !!!",
            // base64 of "u" without a colon.
            "Basic dQ==",
        ] {
            let value = HeaderValue::from_static(value);
            assert!(!auth.permits(Some(&value)).await, "{value:?}");
        }
    }

    #[tokio::test]
    async fn scheme_is_case_insensitive_and_only_the_first_colon_splits() {
        let auth = cheap();
        let value = HeaderValue::from_str(&format!("bAsIc {}", STANDARD.encode("u:pw"))).unwrap();
        assert!(auth.permits(Some(&value)).await);
        assert!(!auth.permits(Some(&header("u", "pw:"))).await);
    }

    #[tokio::test]
    async fn passwords_over_72_bytes_are_rejected_not_truncated() {
        let auth = cheap();
        let long = format!("pw{}", "x".repeat(71));
        assert!(!auth.permits(Some(&header("u", &long))).await);
    }

    #[tokio::test]
    async fn cache_stays_bounded() {
        let auth = cheap();
        for index in 0..=CACHE_SIZE + 5 {
            let password = format!("guess{index}");
            assert!(!auth.permits(Some(&header("u", &password))).await);
        }
        assert!(auth.cache.lock().unwrap().len() <= CACHE_SIZE);
    }

    #[test]
    fn rejects_hashes_that_are_not_bcrypt() {
        // exporter-toolkit v0.20.0 web/testdata/web_config_auth_user_list_invalid.bad.yml
        let error = BasicAuth::new([("john".to_owned(), "doe".to_owned())])
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
