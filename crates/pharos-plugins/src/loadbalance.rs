//! Loadbalance Directive configuration.

use std::{path::PathBuf, time::Duration};

use pharos_corefile::{Cursor, Error};
use pharos_server::{Context, Next, Outcome, Plugin};

#[derive(Debug)]
pub struct LoadBalance {
    pub weight_file: Option<PathBuf>,
    pub reload: Duration,
}

impl LoadBalance {
    pub(crate) fn parse(cursor: &mut Cursor<'_>) -> Result<Self, Error> {
        cursor.next();
        let args = cursor.remaining_args();
        let mut lb = Self {
            weight_file: None,
            reload: Duration::from_secs(30),
        };
        match args.first().map(String::as_str) {
            None | Some("round_robin") if args.len() <= 1 => {}
            Some("weighted") if args.len() == 2 => {
                // shortcut: relative paths use the working directory; join with `root` once that Plugin exists.
                lb.weight_file = Some(PathBuf::from(&args[1]));
                while cursor.next_block() {
                    if cursor.val() != "reload" {
                        return Err(cursor.error("unknown weighted property"));
                    }
                    let args = cursor.remaining_args();
                    if args.len() != 1 {
                        return Err(cursor.arg_err());
                    }
                    lb.reload = crate::health::parse_duration(&args[0])
                        .ok_or_else(|| cursor.error("invalid reload duration"))?;
                }
            }
            _ => return Err(cursor.arg_err()),
        }
        if cursor.next_block() {
            return Err(cursor.error("unknown loadbalance property"));
        }
        Ok(lb)
    }
}

impl Plugin for LoadBalance {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_>, next: N) -> Outcome {
        next.run(cx).await
    }
}
