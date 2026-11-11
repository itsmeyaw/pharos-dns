#[test]
fn compatibility_document_has_parseable_sections() {
    let directives = include_str!("../../pharos-plugins/plugin.cfg")
        .lines()
        .filter_map(|line| line.split_once(':').map(|(name, _)| name))
        .collect::<Vec<_>>();
    let general = [
        "General",
        "CLI",
        "Logging",
        "Metrics",
        "Server",
        "Kubernetes API",
    ];
    let mut in_section = false;
    let mut in_bullet = false;
    for line in include_str!("../../../docs/compatibility.md").lines() {
        if let Some(heading) = line.strip_prefix("## ") {
            assert!(
                directives.contains(&heading) || general.contains(&heading),
                "unknown heading: {heading}"
            );
            in_section = true;
            in_bullet = false;
        } else if in_section && !line.trim().is_empty() {
            if line.starts_with("- ") {
                in_bullet = true;
            } else {
                assert!(
                    in_bullet && line.starts_with("  "),
                    "line outside bullet: {line}"
                );
            }
        }
    }
}

#[test]
fn parses_wrapped_bullets_by_heading() {
    let sections = parse(
        "# title\n\n## cache\n\n- First line\n  continued.\n- Second.\n\n## General\n- Always.\n",
    );
    assert_eq!(
        sections,
        [
            (
                "cache",
                vec!["First line continued.".to_owned(), "Second.".to_owned()]
            ),
            ("General", vec!["Always.".to_owned()])
        ]
    );
}
pub(crate) fn parse(document: &str) -> Vec<(&str, Vec<String>)> {
    let mut sections: Vec<(&str, Vec<String>)> = Vec::new();
    for line in document.lines() {
        if let Some(heading) = line.strip_prefix("## ") {
            sections.push((heading, Vec::new()));
        } else if let Some((_, bullets)) = sections.last_mut() {
            if let Some(text) = line.strip_prefix("- ") {
                bullets.push(text.to_owned());
            } else if line.starts_with("  ") && !line.trim().is_empty() {
                if let Some(bullet) = bullets.last_mut() {
                    bullet.push(' ');
                    bullet.push_str(line.trim());
                }
            }
        }
    }
    sections
}
