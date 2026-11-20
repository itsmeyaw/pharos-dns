//! The process-wide ACME runtime: entries shared between Server Blocks and the challenge state they answer from.

use std::{collections::HashMap, io, sync::Arc};

use pharos_corefile::BlockContext;

use super::{Entry, Solver};
use crate::{Chain, tls::Tls};

/// Every ACME entry of one configuration and the DNS-01 state they share.
// CoreDNS v1.15.0 plugin/tls/acme.go acmeRuntime.
#[derive(Debug)]
pub struct Runtime {
    pub(crate) entries: Vec<Arc<Entry>>,
    pub(crate) solver: Arc<Solver>,
}

/// Merge equivalent ACME entries, reject conflicting ones and make every Server Block answer challenges.
///
/// Returns `None` when no Server Block uses ACME.
// CoreDNS v1.15.0 plugin/tls/acme.go acmeRuntime.add and installChallengeHandlers.
pub(crate) fn link(blocks: &mut [BlockContext<Chain>]) -> io::Result<Option<Arc<Runtime>>> {
    let mut entries: Vec<Arc<Entry>> = Vec::new();
    let mut owners: HashMap<String, usize> = HashMap::new();
    for block in blocks.iter_mut() {
        let Some(tls) = &mut block.config.tls else {
            continue;
        };
        let Some(acme) = tls.acme.take() else {
            continue;
        };
        let index = match entries.iter().position(|known| known.key == acme.key) {
            Some(index) => index,
            None => {
                for domain in &acme.options.domains {
                    if owners.contains_key(domain) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!(
                                "ACME domain {domain:?} is configured with conflicting options"
                            ),
                        ));
                    }
                }
                let index = entries.len();
                for domain in &acme.options.domains {
                    owners.insert(domain.clone(), index);
                }
                entries.push(acme);
                index
            }
        };
        tls.server = Some(entries[index].server());
        tls.acme = Some(Arc::clone(&entries[index]));
    }
    if entries.is_empty() {
        return Ok(None);
    }
    let solver = Arc::new(Solver::default());
    for block in blocks {
        match &mut block.config.tls {
            Some(tls) => tls.answer_challenges(Arc::clone(&solver)),
            None => block.config.tls = Some(Tls::challenge_only(Arc::clone(&solver))),
        }
    }
    Ok(Some(Arc::new(Runtime { entries, solver })))
}

#[cfg(test)]
mod tests {
    use pharos_corefile::{configure, parse};

    use super::link;
    use crate::{Chain, directives};

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/tls");

    fn blocks(text: &str) -> Vec<pharos_corefile::BlockContext<Chain>> {
        let text = text
            .replace("@CERT", &format!("{FIXTURES}/server.pem"))
            .replace("@KEY", &format!("{FIXTURES}/server.key.pem"));
        configure(&parse("Corefile", &text).unwrap(), directives()).unwrap()
    }

    fn acme_block(zone: &str, body: &str) -> String {
        format!("tls://{zone}:853 {{\n tls {{\n  acme {body}\n }}\n whoami\n}}\n")
    }

    // CoreDNS v1.15.0 plugin/tls/acme_test.go TestEquivalentACMEConfigsShareTLSListener.
    #[test]
    fn equivalent_entries_are_merged_and_share_one_identity() {
        let mut blocks = blocks(
            &(acme_block("a.example", "dns.example") + &acme_block("b.example", "dns.example")),
        );
        let runtime = link(&mut blocks).unwrap().unwrap();
        assert_eq!(runtime.entries.len(), 1);
        let first = blocks[0].config.tls.as_ref().unwrap();
        let second = blocks[1].config.tls.as_ref().unwrap();
        assert!(std::sync::Arc::ptr_eq(
            first.acme.as_ref().unwrap(),
            second.acme.as_ref().unwrap()
        ));
        assert_eq!(
            first
                .server
                .as_ref()
                .unwrap()
                .conflict(second.server.as_ref().unwrap()),
            None
        );
    }

    // CoreDNS v1.15.0 plugin/tls/acme_test.go TestACMERuntimeDeduplicatesAndRejectsConflicts.
    #[test]
    fn reordered_domains_are_equivalent() {
        let mut blocks = blocks(
            &(acme_block("a.example", "a.example b.example")
                + &acme_block("b.example", "b.example a.example")),
        );
        assert_eq!(link(&mut blocks).unwrap().unwrap().entries.len(), 1);
    }

    #[test]
    fn a_domain_with_conflicting_options_is_rejected() {
        let mut blocks = blocks(
            &(acme_block("a.example", "a.example b.example")
                + &acme_block("b.example", "a.example\n  email x@example.org")),
        );
        let error = link(&mut blocks).unwrap_err();
        assert!(error.to_string().contains("conflicting options"), "{error}");
    }

    #[test]
    fn different_domains_get_separate_entries() {
        let mut blocks =
            blocks(&(acme_block("a.example", "a.example") + &acme_block("b.example", "b.example")));
        let runtime = link(&mut blocks).unwrap().unwrap();
        assert_eq!(runtime.entries.len(), 2);
        let (first, second) = (
            blocks[0].config.tls.as_ref().unwrap(),
            blocks[1].config.tls.as_ref().unwrap(),
        );
        assert!(
            first
                .server
                .as_ref()
                .unwrap()
                .conflict(second.server.as_ref().unwrap())
                .is_some()
        );
    }

    // CoreDNS v1.15.0 plugin/tls/acme.go installChallengeHandlers: every Server Block answers challenges.
    #[test]
    fn every_block_answers_challenges_once_any_block_uses_acme() {
        let mut blocks = blocks(&format!(
            ".:53 {{\n whoami\n}}\ntls://.:853 {{\n tls @CERT @KEY\n}}\n{}",
            acme_block("c.example", "dns.example")
        ));
        link(&mut blocks).unwrap().unwrap();
        for block in &blocks {
            assert!(block.config.tls.as_ref().unwrap().answers_challenges());
        }
        assert!(blocks[0].config.tls.as_ref().unwrap().server.is_none());
        assert!(blocks[1].config.tls.as_ref().unwrap().server.is_some());
    }

    #[test]
    fn blocks_stay_untouched_without_acme() {
        let mut blocks = blocks(".:53 {\n whoami\n}\ntls://.:853 {\n tls @CERT @KEY\n}\n");
        assert!(link(&mut blocks).unwrap().is_none());
        assert!(blocks[0].config.tls.is_none());
        assert!(!blocks[1].config.tls.as_ref().unwrap().answers_challenges());
    }

    // CoreDNS v1.15.0 plugin/tls/acme_test.go TestACMEDirectiveOrder.
    #[test]
    fn tls_runs_immediately_after_dnssec() {
        let order: Vec<&str> = include_str!("../../../plugin.cfg")
            .lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .filter_map(|line| line.split_once(':').map(|(name, _)| name))
            .collect();
        let position = |name| {
            order
                .iter()
                .position(|candidate| *candidate == name)
                .unwrap()
        };
        assert_eq!(position("tls"), position("dnssec") + 1);
    }
}
