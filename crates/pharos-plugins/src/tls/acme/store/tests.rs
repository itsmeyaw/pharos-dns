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
    assert_eq!(component("*.dns.example"), "%2a.dns.example");
    assert_ne!(component("*.dns.example"), component("_.dns.example"));
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

    let staged = store
        .stage_certificate("*.dns.example", "chain", b"key")
        .unwrap();
    assert!(staged.certificate.is_file());
    assert!(
        store.certificate("*.dns.example").is_none(),
        "a staged pair is not live"
    );
    let key = staged.key.clone();
    assert_eq!(
        std::fs::metadata(&key).unwrap().permissions().mode() & 0o777,
        0o600
    );
    store.commit_certificate(staged).unwrap();
    let live = dir.join("ca.example_14000/certificates/%2a.dns.example");
    assert!(live.join("certificate.pem").is_file() && live.join("key.pem").is_file());
    assert!(
        store.certificate("*.dns.example").is_none(),
        "unparsable chain is not reused"
    );

    // A planted temporary file or symlink is replaced, not written through.
    let target = dir.join("victim");
    std::fs::write(&target, "keep").unwrap();
    std::os::unix::fs::symlink(&target, live.join("key.pem.tmp")).unwrap();
    store
        .stage_certificate("*.dns.example", "chain", b"key2")
        .unwrap();
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");

    // Oversized files are ignored instead of read.
    std::fs::write(
        live.join("certificate.pem"),
        vec![b'x'; super::MAX_STORED as usize + 1],
    )
    .unwrap();
    assert!(store.certificate("*.dns.example").is_none());
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
