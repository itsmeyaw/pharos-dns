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
    // A literal name cannot contain '%', so "%2a" never collides with a name that merely resembles a wildcard.
    let text = text.replace('*', "%2a");
    text.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | '%') {
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
    // A stale or planted temporary file is replaced, never written through: create_new refuses an existing path or symlink.
    match fs::remove_file(&temporary) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(if private { 0o600 } else { 0o644 })
        .open(&temporary)?;
    file.write_all(contents)?;
    file.sync_all()?;
    fs::rename(temporary, path)
}

// Stored PEM files are a few KiB; refuse anything far larger than a certificate chain.
const MAX_STORED: u64 = 1 << 20;

fn read_capped(path: &Path) -> Option<String> {
    (fs::metadata(path).ok()?.len() <= MAX_STORED)
        .then(|| fs::read_to_string(path).ok())
        .flatten()
}

/// A certificate and key written beside the live pair until the caller has checked they load.
pub(crate) struct Staged {
    pub certificate: PathBuf,
    pub key: PathBuf,
    live: (PathBuf, PathBuf),
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
        let pem = read_capped(&self.account_path(email))?;
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
        let pem = read_capped(&certificate)?;
        let (_, leaf) = pem_blocks(&pem)
            .into_iter()
            .find(|(label, _)| label == "CERTIFICATE")?;
        key.is_file().then_some(())?;
        Some((certificate, key, der::validity(&leaf)?))
    }

    /// Write a new chain (PEM) and its key next to the live pair, which stays in place.
    pub(crate) fn stage_certificate(
        &self,
        name: &str,
        chain: &str,
        pkcs8: &[u8],
    ) -> io::Result<Staged> {
        let (certificate, key) = self.certificate_paths(name);
        let staged = (
            certificate.with_extension("pem.new"),
            key.with_extension("pem.new"),
        );
        write(&staged.1, pem_encode("PRIVATE KEY", pkcs8).as_bytes(), true)?;
        write(&staged.0, chain.as_bytes(), false)?;
        Ok(Staged {
            certificate: staged.0,
            key: staged.1,
            live: (certificate, key),
        })
    }

    /// Replace the live pair with the staged one; the key goes first so a chain never lacks its key.
    pub(crate) fn commit_certificate(&self, staged: Staged) -> io::Result<()> {
        fs::rename(&staged.key, &staged.live.1)?;
        fs::rename(&staged.certificate, &staged.live.0)
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
mod tests;
