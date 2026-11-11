//! Server-side search path completion.

use pharos_corefile::{Cursor, Error, origins_from_args_or_server_block};
use pharos_server::{Context, Next, Outcome, Plugin};

#[derive(Debug)]
pub struct AutoPath {
    pub(crate) domains: Vec<String>,
    pub(crate) search: Vec<String>,
    pub(crate) provider: Option<String>,
}

impl AutoPath {
    pub(crate) fn parse(cursor: &mut Cursor<'_>, domains: &[&str]) -> Result<Self, Error> {
        cursor.next();
        let args = cursor.remaining_args();
        let (source, zones) = args.split_last().ok_or_else(|| cursor.arg_err())?;
        let mut search = Vec::new();
        let provider = if let Some(provider) = source.strip_prefix('@') {
            Some(provider.to_owned())
        } else {
            let file =
                std::fs::read_to_string(source).map_err(|err| cursor.error(err.to_string()))?;
            for line in file.lines() {
                let fields = line.split_whitespace().collect::<Vec<_>>();
                match fields.first().copied() {
                    Some("domain") => {
                        search = fields.get(1).into_iter().map(|s| (*s).to_owned()).collect()
                    }
                    Some("search") => {
                        search = fields[1..].iter().map(|s| (*s).to_owned()).collect()
                    }
                    _ => {}
                }
            }
            for suffix in &mut search {
                if !suffix.ends_with('.') {
                    suffix.push('.');
                }
            }
            search.push(String::new());
            None
        };
        let domains = origins_from_args_or_server_block(
            &zones.iter().map(String::as_str).collect::<Vec<_>>(),
            domains,
        );
        Ok(Self {
            domains,
            search,
            provider,
        })
    }
}

impl Plugin for AutoPath {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        next.run(cx).await
    }
}
