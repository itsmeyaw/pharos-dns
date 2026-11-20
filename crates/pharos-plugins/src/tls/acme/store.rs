//! Where ACME keeps account keys, certificates and their private keys.
//!
//! The layout is Pharos's own: `<storage>/<ca>/accounts/<email>.key` and
//! `<storage>/<ca>/certificates/<name>/{certificate.pem,key.pem}`.

use std::{
    fs, io,
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::SystemTime,
};

use base64::{Engine, engine::general_purpose::STANDARD};

use super::{Options, der};

/// The storage subtree of one CA.
pub(crate) struct Store {
    root: PathBuf,
}

// RFC 7468 §2: PEM lines are 64 characters except the last.
const PEM_LINE: usize = 64;

/// RFC 7468 §3: the PEM texts of `label` blocks in `pem`, decoded; malformed blocks are skipped.
pub(crate) fn pem_blocks(pem: &str) -> Vec<(String, Vec<u8>)> {
    let mut blocks = Vec::new();
    let mut current: Option<(String, String)> = None;
    for line in pem.lines().map(str::trim) {
        if let Some(label) = line
            .strip_prefix("-----BEGIN ")
            .and_then(|rest| rest.strip_suffix("-----"))
        {
            current = Some((label.to_owned(), String::new()));
        } else if line.starts_with("-----END ") {
            if let Some((label, text)) = current.take()
                && let Ok(der) = STANDARD.decode(text)
            {
                blocks.push((label, der));
            }
        } else if let Some((_, text)) = &mut current {
            text.push_str(line);
        }
    }
    blocks
}

pub(crate) fn pem_encode(label: &str, der: &[u8]) -> String {
    let text = STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for chunk in text.as_bytes().chunks(PEM_LINE) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    pem
}

// Keep a name usable as one path component: only DNS characters and e-mail punctuation survive.
fn component(text: &str) -> String {
    let text = text.replace('*', "wildcard_");
    text.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@') {
                c
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_start_matches('.')
        .to_owned()
}

/// Write `contents` so a reader sees the old or the new file, never a partial one.
fn write(path: &Path, contents: &[u8], private: bool) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("tmp");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(if private { 0o600 } else { 0o644 })
        .open(&temporary)?;
    file.write_all(contents)?;
    file.sync_all()?;
    fs::rename(temporary, path)
}

impl Store {
    pub(crate) fn new(options: &Options) -> Self {
        let host = options
            .ca
            .split_once("://")
            .map_or(options.ca.as_str(), |(_, rest)| rest)
            .split('/')
            .next()
            .unwrap_or_default();
        Self {
            root: options.storage.join(component(host)),
        }
    }

    fn account_path(&self, email: Option<&str>) -> PathBuf {
        self.root
            .join("accounts")
            .join(format!("{}.key", component(email.unwrap_or("default"))))
    }

    fn certificate_paths(&self, name: &str) -> (PathBuf, PathBuf) {
        let dir = self.root.join("certificates").join(component(name));
        (dir.join("certificate.pem"), dir.join("key.pem"))
    }

    /// The PKCS#8 account key of `email`, if one was saved.
    pub(crate) fn account(&self, email: Option<&str>) -> Option<Vec<u8>> {
        let pem = fs::read_to_string(self.account_path(email)).ok()?;
        pem_blocks(&pem)
            .into_iter()
            .find(|(label, _)| label == "PRIVATE KEY")
            .map(|(_, der)| der)
    }

    pub(crate) fn save_account(&self, email: Option<&str>, pkcs8: &[u8]) -> io::Result<()> {
        write(
            &self.account_path(email),
            pem_encode("PRIVATE KEY", pkcs8).as_bytes(),
            true,
        )
    }

    /// The paths of the saved certificate chain and key of `name`, and when that certificate ends.
    pub(crate) fn certificate(&self, name: &str) -> Option<(PathBuf, PathBuf, der::Validity)> {
        let (certificate, key) = self.certificate_paths(name);
        let pem = fs::read_to_string(&certificate).ok()?;
        let (_, leaf) = pem_blocks(&pem)
            .into_iter()
            .find(|(label, _)| label == "CERTIFICATE")?;
        key.is_file().then_some(())?;
        Some((certificate, key, der::validity(&leaf)?))
    }

    /// Save a new chain (PEM) and its key; the key goes first so a chain never lacks its key.
    pub(crate) fn save_certificate(
        &self,
        name: &str,
        chain: &str,
        pkcs8: &[u8],
    ) -> io::Result<(PathBuf, PathBuf)> {
        let (certificate, key) = self.certificate_paths(name);
        write(&key, pem_encode("PRIVATE KEY", pkcs8).as_bytes(), true)?;
        write(&certificate, chain.as_bytes(), false)?;
        Ok((certificate, key))
    }
}

/// When to renew a certificate valid over `validity`: with a third of its lifetime left.
// certmagic v0.25 DefaultRenewalWindowRatio: renew when the remaining lifetime falls to 1/3.
pub(crate) fn renewal_time(validity: &der::Validity) -> SystemTime {
    let lifetime = validity
        .not_after
        .duration_since(validity.not_before)
        .unwrap_or_default();
    validity.not_after - lifetime / 3
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::fs::PermissionsExt,
        path::PathBuf,
        time::{Duration, UNIX_EPOCH},
    };

    use super::{Store, component, pem_blocks, pem_encode, renewal_time};
    use crate::tls::acme::{Options, der::Validity};

    fn options(storage: PathBuf) -> Options {
        Options {
            domains: vec!["dns.example".into()],
            email: None,
            ca: "https://ca.example:14000/dir".into(),
            storage,
            ca_root: None,
            resolver: None,
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("pharos-acme-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    // RFC 7468 §3: 64-character lines between the encapsulation boundaries.
    #[test]
    fn pem_round_trips_and_wraps_at_64() {
        let der: Vec<u8> = (0..=255).collect();
        let pem = pem_encode("CERTIFICATE", &der);
        assert!(pem.lines().all(|line| line.len() <= 64));
        assert_eq!(
            pem_blocks(&format!("{pem}junk\n{pem}")),
            vec![("CERTIFICATE".to_owned(), der.clone()); 2]
        );
        assert!(pem_blocks("-----BEGIN X-----\n!!!\n-----END X-----\n").is_empty());
    }

    #[test]
    fn names_become_single_path_components() {
        assert_eq!(component("*.dns.example"), "wildcard_.dns.example");
        assert_eq!(component("../etc/passwd"), "_etc_passwd");
        assert_eq!(component("a@b.example"), "a@b.example");
    }

    #[test]
    fn account_and_certificate_survive_a_restart_and_keys_are_private() {
        let dir = scratch("store");
        let store = Store::new(&options(dir.clone()));
        assert!(store.account(None).is_none());
        store.save_account(None, b"pkcs8").unwrap();
        assert_eq!(
            Store::new(&options(dir.clone())).account(None).unwrap(),
            b"pkcs8"
        );
        assert!(dir.join("ca.example_14000/accounts/default.key").is_file());

        let (certificate, key) = store
            .save_certificate("*.dns.example", "chain", b"key")
            .unwrap();
        assert_eq!(
            std::fs::metadata(key).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(certificate.ends_with("certificates/wildcard_.dns.example/certificate.pem"));
        assert!(
            store.certificate("*.dns.example").is_none(),
            "unparsable chain is not reused"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    // certmagic v0.25 DefaultRenewalWindowRatio: one third of the lifetime remaining.
    #[test]
    fn renewal_starts_with_a_third_of_the_lifetime_left() {
        let at = |days: u64| UNIX_EPOCH + Duration::from_secs(days * 86_400);
        let validity = Validity {
            not_before: at(0),
            not_after: at(90),
        };
        assert_eq!(renewal_time(&validity), at(60));
    }
}
