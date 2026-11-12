//! Compiled Go-template expressions used by the template Plugin.

use pharos_server::Metadata;
use std::fmt::{self, Write};

/// Borrowed template values for a Query.
pub struct Data<'a, 'm> {
    pub name: &'a str,
    pub metadata: &'a Metadata<'m>,
}

enum Part {
    Text(String),
    Name,
    Metadata(String),
}

/// A template parsed at setup time.
pub struct Template(Vec<Part>);

impl Template {
    /// Compile the supported template actions.
    pub fn compile(mut source: &str) -> Result<Self, String> {
        let mut parts = Vec::new();
        while let Some(start) = source.find("{{") {
            parts.push(Part::Text(source[..start].to_owned()));
            source = &source[start + 2..];
            let end = source.find("}}").ok_or("unclosed template action")?;
            let action = source[..end].trim();
            let part = if action == ".Name" {
                Part::Name
            } else if let Some(label) = action.strip_prefix(".Meta ") {
                let label = label.trim();
                let label = label
                    .strip_prefix('"')
                    .and_then(|s| s.strip_suffix('"'))
                    .ok_or("unsupported .Meta argument")?;
                Part::Metadata(label.to_owned())
            } else {
                return Err(format!("unsupported template action: {action}"));
            };
            parts.push(part);
            source = &source[end + 2..];
        }
        parts.push(Part::Text(source.to_owned()));
        Ok(Self(parts))
    }

    /// Append the rendered template to a caller-provided buffer.
    pub fn render(&self, data: &Data<'_, '_>, output: &mut String) -> fmt::Result {
        for part in &self.0 {
            output.write_str(match part {
                Part::Text(text) => text,
                Part::Name => data.name,
                Part::Metadata(label) => data.metadata.get(label).unwrap_or(""),
            })?;
        }
        Ok(())
    }
}
