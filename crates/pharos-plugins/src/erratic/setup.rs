use pharos_corefile::{BlockContext, Cursor, Error};
use std::time::Duration;

pub(crate) fn setup(
    cursor: &mut Cursor<'_>,
    block: &mut BlockContext<crate::Chain>,
) -> Result<(), Error> {
    let mut erratic = super::Erratic::default();
    let mut explicit_drop = false;
    cursor.next();
    while cursor.next_block() {
        let option = cursor.val().to_owned();
        let args = cursor.remaining_args();
        match option.as_str() {
            "drop" => {
                if args.len() > 1 {
                    return Err(cursor.arg_err());
                }
                if let Some(amount) = args.first() {
                    erratic.drop = parse_amount(cursor, amount)?;
                    explicit_drop = true;
                }
            }
            "delay" => {
                if args.len() > 2 {
                    return Err(cursor.arg_err());
                }
                erratic.delay = 2;
                erratic.duration = Duration::from_millis(100);
                if let Some(amount) = args.first() {
                    erratic.delay = parse_amount(cursor, amount)?;
                }
                if let Some(duration) = args.get(1) {
                    erratic.duration = crate::health::parse_duration(duration)
                        .ok_or_else(|| cursor.error("invalid duration"))?;
                }
            }
            "truncate" => {
                if args.len() > 1 {
                    return Err(cursor.arg_err());
                }
                erratic.truncate = 2;
                if let Some(amount) = args.first() {
                    erratic.truncate = parse_amount(cursor, amount)?;
                }
            }
            "large" => erratic.large = true,
            _ => return Err(cursor.error(format!("unknown property '{option}'"))),
        }
    }
    if (erratic.delay > 0 || erratic.truncate > 0) && !explicit_drop {
        erratic.drop = 0;
    }
    block.config.erratic = Some(erratic);
    Ok(())
}

fn parse_amount(cursor: &Cursor<'_>, input: &str) -> Result<u64, Error> {
    input
        .parse::<i32>()
        .ok()
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| cursor.error("invalid amount"))
}
