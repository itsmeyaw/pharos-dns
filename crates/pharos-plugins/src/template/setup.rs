use pharos_corefile::{
    BlockContext, Cursor, Error, Fallthrough, origins_from_args_or_server_block,
};
use pharos_proto::{Class, Rcode, Type};

use super::{Rule, Template, TemplateRecord, Variable};
use crate::{Chain, expression, gotemplate};

pub(crate) fn setup(cursor: &mut Cursor<'_>, block: &mut BlockContext<Chain>) -> Result<(), Error> {
    let domains = block
        .keys()
        .iter()
        .map(|key| key.domain.as_str())
        .collect::<Vec<_>>();
    let mut rules = Vec::new();
    while cursor.next() {
        let args = cursor.remaining_args();
        if args.len() < 2 {
            return Err(cursor.arg_err());
        }
        let class = if args[0] == "ANY" {
            Some(Class::ANY)
        } else {
            Class::from_mnemonic(&args[0])
                .filter(|class| class.to_string() == args[0] && *class != Class::ANY)
        }
        .ok_or_else(|| cursor.error("invalid class"))?;
        let qtype = Type::from_mnemonic(&args[1])
            .filter(|qtype| qtype.to_string() == args[1])
            .ok_or_else(|| cursor.error("invalid type"))?;
        let zones = origins_from_args_or_server_block(
            &args[2..].iter().map(String::as_str).collect::<Vec<_>>(),
            &domains,
        );
        let mut rule = Rule {
            class,
            qtype,
            zones,
            regex: Vec::new(),
            records: Vec::new(),
            variables: Vec::new(),
            expressions: Vec::new(),
            rcode: Rcode::NOERROR,
            ederror: None,
            fallthrough: Fallthrough::default(),
        };
        while cursor.next_block() {
            let option = cursor.val().to_owned();
            let args = cursor.remaining_args();
            match option.as_str() {
                "match" if !args.is_empty() => {
                    for pattern in args {
                        if pattern.len() > 10_000 {
                            return Err(cursor.error("regex pattern too long"));
                        }
                        rule.regex
                            .push(super::Matcher::new(&pattern).map_err(|e| cursor.error(e))?);
                    }
                }
                "answer" | "authority" | "additional" if !args.is_empty() => {
                    for source in args {
                        let compiled =
                            gotemplate::Template::compile(&source).map_err(|e| cursor.error(e))?;
                        rule.records.push(TemplateRecord {
                            section: match option.as_str() {
                                "answer" => pharos_proto::Section::Answer,
                                "authority" => pharos_proto::Section::Authority,
                                _ => pharos_proto::Section::Additional,
                            },
                            source,
                            compiled,
                        });
                    }
                }
                "var" if args.len() >= 2 => {
                    if rule.variables.len() == 32 {
                        return Err(cursor.error("too many template variables (maximum 32)"));
                    }
                    let name = &args[0];
                    if !valid_variable(name)
                        || rule.variables.iter().any(|variable| variable.name == *name)
                    {
                        return Err(cursor.error("invalid or duplicate variable name"));
                    }
                    let types = rule
                        .variables
                        .iter()
                        .map(|v| (v.name.as_str(), v.expression.value_type()))
                        .collect::<Vec<_>>();
                    let expression = expression::Expression::compile_with_variables(
                        &args[1..].join(" "),
                        &types,
                    )
                    .map_err(|e| cursor.error(e))?;
                    rule.variables.push(Variable {
                        name: name.clone(),
                        expression,
                    });
                }
                "expr" if !args.is_empty() => {
                    let types = rule
                        .variables
                        .iter()
                        .map(|v| (v.name.as_str(), v.expression.value_type()))
                        .collect::<Vec<_>>();
                    rule.expressions.push(
                        expression::Expression::compile_with_variables(&args.join(" "), &types)
                            .map_err(|e| cursor.error(e))?,
                    );
                }
                "rcode" if !args.is_empty() => {
                    // CoreDNS accepts the NOTIMPL alias that miekg/dns keeps for NOTIMP.
                    let rcode = if args[0] == "NOTIMPL" {
                        Some(Rcode::NOTIMP)
                    } else {
                        Rcode::from_mnemonic(&args[0]).filter(|rcode| rcode.to_string() == args[0])
                    };
                    rule.rcode = rcode.ok_or_else(|| cursor.error("unknown rcode"))?
                }
                "ederror" if (1..=2).contains(&args.len()) => {
                    rule.ederror = Some((
                        args[0]
                            .parse()
                            .map_err(|_| cursor.error("invalid extended error"))?,
                        args.get(1).cloned().unwrap_or_default(),
                    ))
                }
                "fallthrough" => rule
                    .fallthrough
                    .set_domains_from_args(&args.iter().map(String::as_str).collect::<Vec<_>>()),
                "upstream" => {}
                _ => return Err(cursor.arg_err()),
            }
        }
        if rule.regex.is_empty() {
            rule.regex
                .push(super::Matcher::new(".*").map_err(|e| cursor.error(e))?);
        }
        rules.push(rule);
    }
    block.config.template = Some(Template::new(rules));
    Ok(())
}

fn valid_variable(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && !matches!(
            name,
            "name"
                | "type"
                | "class"
                | "proto"
                | "size"
                | "client_ip"
                | "port"
                | "id"
                | "opcode"
                | "do"
                | "bufsize"
                | "server_ip"
                | "server_port"
                | "metadata"
                | "incidr"
                | "group"
                | "all"
                | "none"
                | "any"
                | "one"
                | "filter"
                | "map"
                | "find"
                | "findIndex"
                | "findLast"
                | "findLastIndex"
                | "count"
                | "sum"
                | "groupBy"
                | "sortBy"
                | "reduce"
                | "len"
                | "abs"
                | "ceil"
                | "floor"
                | "round"
                | "int"
                | "float"
                | "string"
                | "trim"
                | "trimPrefix"
                | "trimSuffix"
                | "upper"
                | "lower"
                | "split"
                | "splitAfter"
                | "replace"
                | "repeat"
                | "join"
                | "indexOf"
                | "lastIndexOf"
                | "hasPrefix"
                | "hasSuffix"
                | "max"
                | "min"
                | "mean"
                | "median"
                | "toJSON"
                | "fromJSON"
                | "toBase64"
                | "fromBase64"
                | "now"
                | "duration"
                | "date"
                | "timezone"
                | "first"
                | "last"
                | "get"
                | "take"
                | "keys"
                | "values"
                | "toPairs"
                | "fromPairs"
                | "reverse"
                | "uniq"
                | "concat"
                | "flatten"
                | "sort"
                | "bitnot"
                | "true"
                | "false"
                | "nil"
                | "let"
                | "if"
                | "else"
                | "not"
                | "and"
                | "or"
                | "in"
                | "matches"
                | "contains"
                | "startsWith"
                | "endsWith"
        )
}

#[cfg(test)]
mod tests {
    use super::valid_variable;

    #[test]
    fn rejects_expression_builtins_and_keywords_as_variables() {
        for name in [
            "findLast", "all", "fromJSON", "if", "matches", "group", "name", "1bad", "a-b",
        ] {
            assert!(!valid_variable(name), "{name}");
        }
        for name in ["_name", "value", "Group", "x1"] {
            assert!(valid_variable(name), "{name}");
        }
    }
}
