//! Docker state domain: ownership of containers by label.
//!
//! This module talks to Docker only through its command-line client, and only
//! ever looks at resources that carry TemporalTrail's ownership labels, so it
//! can never touch containers that belong to anyone else.

use std::fmt;
use std::process::Command;

/// Marks a container as created and owned by TemporalTrail.
pub const LABEL_MANAGED: &str = "temporaltrail.managed";
/// Records which timeline a managed container belongs to.
pub const LABEL_TIMELINE: &str = "temporaltrail.timeline";

const LISTING_FIELD_SEPARATOR: char = '\t';
const LISTING_FIELD_COUNT: usize = 5;
const MAX_TIMELINE_NAME_LENGTH: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DockerError {
    InvalidTimelineName(String),
    CommandFailed(String),
}

impl fmt::Display for DockerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DockerError::InvalidTimelineName(name) => write!(f, "invalid timeline name: {name}"),
            DockerError::CommandFailed(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for DockerError {}

/// A container created and owned by TemporalTrail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedContainer {
    pub id: String,
    pub name: String,
    pub image: String,
    pub state: String,
    pub timeline: String,
}

/// Timeline names end up in Docker filter arguments, so they must be boring:
/// letters, digits, '_' and '-' only.
fn validate_timeline_name(name: &str) -> Result<(), DockerError> {
    let is_valid = !name.is_empty()
        && name.len() <= MAX_TIMELINE_NAME_LENGTH
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if is_valid {
        Ok(())
    } else {
        Err(DockerError::InvalidTimelineName(name.to_string()))
    }
}

/// The Go-template format string that makes `docker ps` print one
/// tab-separated line per container, in the order `parse_container_listing` expects.
fn container_listing_format() -> String {
    let timeline_label_field = format!("{{{{.Label \"{LABEL_TIMELINE}\"}}}}");
    [
        "{{.ID}}",
        "{{.Names}}",
        "{{.Image}}",
        "{{.State}}",
        timeline_label_field.as_str(),
    ]
    .join("\t")
}

/// Turns the output of `docker ps` (in our tab-separated format) into containers.
/// Lines that do not have exactly the expected fields are skipped.
pub fn parse_container_listing(output: &str) -> Vec<ManagedContainer> {
    output
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(LISTING_FIELD_SEPARATOR).collect();
            if fields.len() != LISTING_FIELD_COUNT {
                return None;
            }
            Some(ManagedContainer {
                id: fields[0].to_string(),
                name: fields[1].to_string(),
                image: fields[2].to_string(),
                state: fields[3].to_string(),
                timeline: fields[4].to_string(),
            })
        })
        .collect()
}

/// Lists containers owned by TemporalTrail, running or stopped.
/// With `Some(timeline)`, only that timeline's containers are returned.
pub fn list_managed_containers(
    timeline: Option<&str>,
) -> Result<Vec<ManagedContainer>, DockerError> {
    let mut command = Command::new("sudo");
    command.args(["docker", "ps", "--all", "--filter"]);
    command.arg(format!("label={LABEL_MANAGED}=true"));
    if let Some(name) = timeline {
        validate_timeline_name(name)?;
        command.arg("--filter");
        command.arg(format!("label={LABEL_TIMELINE}={name}"));
    }
    command.arg("--format");
    command.arg(container_listing_format());

    let output = command
        .output()
        .map_err(|error| DockerError::CommandFailed(format!("could not run docker: {error}")))?;
    if !output.status.success() {
        return Err(DockerError::CommandFailed(format!(
            "docker ps failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(parse_container_listing(&String::from_utf8_lossy(&output.stdout)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_container_listing_lines() {
        let output = "abc123\ttt-probe-a\talpine\trunning\tscratch-1\n\
                      def456\ttt-probe-b\tnginx\texited\tscratch-2\n";
        let containers = parse_container_listing(output);
        assert_eq!(containers.len(), 2);
        assert_eq!(containers[0].name, "tt-probe-a");
        assert_eq!(containers[0].timeline, "scratch-1");
        assert_eq!(containers[1].image, "nginx");
        assert_eq!(containers[1].state, "exited");
    }

    #[test]
    fn skips_malformed_listing_lines() {
        let output = "\nonly\tthree\tfields\nabc123\ta\tb\trunning\tscratch-1\n";
        let containers = parse_container_listing(output);
        assert_eq!(containers.len(), 1);
        assert_eq!(containers[0].id, "abc123");
    }

    #[test]
    fn rejects_invalid_timeline_names() {
        for invalid in ["", "bad name", "x; rm -rf /", "a/b", &"x".repeat(33)] {
            assert!(
                validate_timeline_name(invalid).is_err(),
                "should reject: {invalid:?}"
            );
        }
        assert!(validate_timeline_name("trial-1_ok").is_ok());
    }

    #[test]
    fn listing_format_includes_ownership_label() {
        assert_eq!(
            container_listing_format(),
            "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.State}}\t{{.Label \"temporaltrail.timeline\"}}"
        );
    }
}