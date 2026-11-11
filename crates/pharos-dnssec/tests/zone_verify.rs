use std::{
    io::Write,
    process::{Command, Stdio},
};

use aws_lc_rs::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use pharos_dnssec::{
    canonical::{CanonicalRecord, signed_data},
    denial::{ZoneName, nsec_chain},
    digest::key_tag,
    sign::SigningKey,
};
use pharos_proto::{Class, Name, NameRef, Rdata, Type};

fn name_ref(name: &Name) -> NameRef<'_> {
    NameRef::parse(name.as_wire(), 0).unwrap()
}

fn append_rr(
    zone: &mut String,
    owner: &Name,
    signer: &Name,
    key: &SigningKey,
    tag: u16,
    rdata: Rdata<'_>,
    presentation: &str,
) {
    let labels = owner.label_count() as u8;
    let rtype = rdata.rtype();
    let sig = Rdata::Rrsig {
        type_covered: rtype,
        algorithm: 15,
        labels,
        original_ttl: 300,
        expiration: 2_000_000_000,
        inception: 1_600_000_000,
        key_tag: tag,
        signer: name_ref(signer),
        signature: &[],
    };
    let data = signed_data(
        &sig,
        &[CanonicalRecord {
            owner: name_ref(owner),
            class: Class::IN,
            data: rdata,
        }],
    )
    .unwrap();
    let signature = STANDARD.encode(key.sign(&data).unwrap());
    zone.push_str(&format!("{owner} 300 IN {rtype} {presentation}\n{owner} 300 IN RRSIG {rtype} 15 {labels} 300 20330518033320 20200913122640 {tag} {signer} {signature}\n"));
}

#[test]
fn generated_zone_verifies_with_ldns_when_available() {
    if Command::new("ldns-verify-zone").arg("-v").output().is_err() {
        eprintln!("ldns-verify-zone unavailable; external verification skipped");
        return;
    }
    let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let public = Ed25519KeyPair::from_pkcs8(key.as_ref()).unwrap();
    let signer = SigningKey::from_pkcs8(15, key.as_ref()).unwrap();
    let apex: Name = "example.org.".parse().unwrap();
    let ns: Name = "ns.example.org.".parse().unwrap();
    let hostmaster: Name = "hostmaster.example.org.".parse().unwrap();
    let www: Name = "www.example.org.".parse().unwrap();
    let dnskey = Rdata::Dnskey {
        flags: 257,
        protocol: 3,
        algorithm: 15,
        public_key: public.public_key().as_ref(),
    };
    let mut wire = vec![1, 1, 3, 15];
    wire.extend_from_slice(public.public_key().as_ref());
    let tag = key_tag(&wire).unwrap();
    let mut zone = String::new();
    append_rr(
        &mut zone,
        &apex,
        &apex,
        &signer,
        tag,
        Rdata::Soa {
            mname: name_ref(&ns),
            rname: name_ref(&hostmaster),
            serial: 1,
            refresh: 3600,
            retry: 600,
            expire: 86400,
            minimum: 300,
        },
        "ns.example.org. hostmaster.example.org. 1 3600 600 86400 300",
    );
    append_rr(
        &mut zone,
        &apex,
        &apex,
        &signer,
        tag,
        Rdata::Ns(name_ref(&ns)),
        "ns.example.org.",
    );
    append_rr(
        &mut zone,
        &apex,
        &apex,
        &signer,
        tag,
        dnskey,
        &format!("257 3 15 {}", STANDARD.encode(public.public_key().as_ref())),
    );
    append_rr(
        &mut zone,
        &ns,
        &apex,
        &signer,
        tag,
        Rdata::A("192.0.2.1".parse().unwrap()),
        "192.0.2.1",
    );
    append_rr(
        &mut zone,
        &www,
        &apex,
        &signer,
        tag,
        Rdata::A("192.0.2.2".parse().unwrap()),
        "192.0.2.2",
    );
    let entries = [
        ZoneName {
            name: apex.clone(),
            types: vec![Type::SOA, Type::NS, Type::DNSKEY],
        },
        ZoneName {
            name: ns,
            types: vec![Type::A],
        },
        ZoneName {
            name: www,
            types: vec![Type::A],
        },
    ];
    for nsec in nsec_chain(&apex, &entries).unwrap() {
        let types = if nsec.owner == apex {
            "NS SOA RRSIG NSEC DNSKEY"
        } else {
            "A RRSIG NSEC"
        };
        append_rr(
            &mut zone,
            &nsec.owner,
            &apex,
            &signer,
            tag,
            nsec.rdata(),
            &format!("{} {types}", nsec.next),
        );
    }
    let mut child = Command::new("ldns-verify-zone")
        .args(["-t", "20250101000000"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(zone.as_bytes())
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}\n{}\n{zone}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}
