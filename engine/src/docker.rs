//! Docker state domain: ownership of containers and volumes by label, and
//! capture of their state for checkpoints.
//!
//! This module talks to Docker only through its command-line client, and only
//! ever acts on resources that carry TemporalTrail's ownership labels, so it
//! can never touch containers or volumes that belong to anyone else.

use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Marks a container or volume as created and owned by TemporalTrail.
pub const LABEL_MANAGED: &str = "temporaltrail.managed";
/// Records which timeline a managed container or volume belongs to.
pub const LABEL_TIMELINE: &str = "temporaltrail.timeline";
/// Repository prefix for the images that hold captured container layers.
pub const SNAPSHOT_IMAGE_REPOSITORY_PREFIX: &str = "temporaltrail-snapshot";

const LISTING_FIELD_SEPARATOR: char = '\t';
const LISTING_FIELD_COUNT: usize = 5;
const MAX_TIMELINE_NAME_LENGTH: usize = 32;
const MAX_RESOURCE_NAME_LENGTH: usize = 64;
const VOLUME_ARCHIVE_EXTENSION: &str = "tar";
const ARCHIVE_COPY_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DockerError {
    InvalidTimelineName(String),
    InvalidResourceName(String),
    NotManaged(String),
    CommandFailed(String),
}

impl fmt::Display for DockerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DockerError::InvalidTimelineName(name) => write!(f, "invalid timeline name: {name}"),
            DockerError::InvalidResourceName(name) => write!(f, "invalid container, volume or tag name: {name}"),
            DockerError::NotManaged(name) => write!(
                f,
                "'{name}' is not managed by TemporalTrail (it has no {LABEL_MANAGED} label)"
            ),
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

/// Everything saved from one container at checkpoint time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerCapture {
    pub container_name: String,
    pub image_reference: String,
    pub image_id: String,
    /// Raw `docker inspect` output (a JSON array holding one object), kept as
    /// text so it can be stored exactly as Docker reported it.
    pub inspect_json: String,
}

/// The result of archiving one managed volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeCapture {
    pub volume_name: String,
    /// SHA-256 of the archive in lowercase hex; also the archive's file name.
    pub content_hash: String,
    pub archive_path: PathBuf,
    pub size_bytes: u64,
    /// True when an identical archive was already in the store, so nothing new was written.
    pub already_stored: bool,
}

// ---------------------------------------------------------------------------
// Input validation: anything that reaches a Docker command must be boring.
// ---------------------------------------------------------------------------

/// Timeline names: letters, digits, '_' and '-' only.
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

/// Container names that can safely become part of an image repository name:
/// lowercase letters, digits, '-', '_' and '.', starting with a letter or digit.
fn validate_container_name(name: &str) -> Result<(), DockerError> {
    let mut characters = name.chars();
    let starts_correctly = characters
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    let rest_is_valid = characters
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_' || c == '.');
    if starts_correctly && rest_is_valid && name.len() <= MAX_RESOURCE_NAME_LENGTH {
        Ok(())
    } else {
        Err(DockerError::InvalidResourceName(name.to_string()))
    }
}

/// Volume names: letters, digits, '-', '_' and '.', starting with a letter or digit.
fn validate_volume_name(name: &str) -> Result<(), DockerError> {
    let mut characters = name.chars();
    let starts_correctly = characters.next().is_some_and(|c| c.is_ascii_alphanumeric());
    let rest_is_valid =
        characters.all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.');
    if starts_correctly && rest_is_valid && name.len() <= MAX_RESOURCE_NAME_LENGTH {
        Ok(())
    } else {
        Err(DockerError::InvalidResourceName(name.to_string()))
    }
}

/// Image tags: letters, digits, '_', '.' and '-', not starting with '.' or '-'.
fn validate_snapshot_tag(tag: &str) -> Result<(), DockerError> {
    let mut characters = tag.chars();
    let starts_correctly = characters
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
    let rest_is_valid =
        characters.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-');
    if starts_correctly && rest_is_valid && tag.len() <= MAX_RESOURCE_NAME_LENGTH {
        Ok(())
    } else {
        Err(DockerError::InvalidResourceName(tag.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Running Docker
// ---------------------------------------------------------------------------

/// Builds the error converter for file-system failures, prefixed with what was being attempted.
fn io_failure(context: &'static str) -> impl Fn(std::io::Error) -> DockerError {
    move |error| DockerError::CommandFailed(format!("{context}: {error}"))
}

/// Runs `sudo docker <arguments>` and returns its standard output.
fn run_docker<I, S>(arguments: I) -> Result<String, DockerError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new("sudo")
        .arg("docker")
        .args(arguments)
        .output()
        .map_err(|error| DockerError::CommandFailed(format!("could not run docker: {error}")))?;
    if !output.status.success() {
        return Err(DockerError::CommandFailed(format!(
            "docker failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

// ---------------------------------------------------------------------------
// Listing owned containers
// ---------------------------------------------------------------------------

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
    let mut arguments: Vec<String> = vec![
        "ps".into(),
        "--all".into(),
        "--filter".into(),
        format!("label={LABEL_MANAGED}=true"),
    ];
    if let Some(name) = timeline {
        validate_timeline_name(name)?;
        arguments.push("--filter".into());
        arguments.push(format!("label={LABEL_TIMELINE}={name}"));
    }
    arguments.push("--format".into());
    arguments.push(container_listing_format());
    let output = run_docker(&arguments)?;
    Ok(parse_container_listing(&output))
}

// ---------------------------------------------------------------------------
// Capturing a container
// ---------------------------------------------------------------------------

/// The image name a container's captured layer is stored under,
/// e.g. `temporaltrail-snapshot/web-1:checkpoint-3`.
pub fn snapshot_image_reference(container_name: &str, tag: &str) -> Result<String, DockerError> {
    validate_container_name(container_name)?;
    validate_snapshot_tag(tag)?;
    Ok(format!("{SNAPSHOT_IMAGE_REPOSITORY_PREFIX}/{container_name}:{tag}"))
}

fn is_container_managed(container_name: &str) -> Result<bool, DockerError> {
    let format_argument = format!("{{{{index .Config.Labels \"{LABEL_MANAGED}\"}}}}");
    let label_value = run_docker([
        "inspect",
        "--format",
        format_argument.as_str(),
        container_name,
    ])?;
    Ok(label_value.trim() == "true")
}

/// Saves a managed container's configuration and commits its layer changes to
/// a snapshot image. Refuses containers that TemporalTrail does not own.
/// Volumes are not part of the layer and are captured separately.
pub fn capture_container(container_name: &str, tag: &str) -> Result<ContainerCapture, DockerError> {
    let image_reference = snapshot_image_reference(container_name, tag)?;
    if !is_container_managed(container_name)? {
        return Err(DockerError::NotManaged(container_name.to_string()));
    }
    let inspect_json = run_docker(["inspect", container_name])?;
    let image_id = run_docker(["commit", container_name, image_reference.as_str()])?;
    Ok(ContainerCapture {
        container_name: container_name.to_string(),
        image_reference,
        image_id: image_id.trim().to_string(),
        inspect_json,
    })
}

// ---------------------------------------------------------------------------
// Capturing a volume
// ---------------------------------------------------------------------------

fn is_volume_managed(volume_name: &str) -> Result<bool, DockerError> {
    let format_argument = format!("{{{{index .Labels \"{LABEL_MANAGED}\"}}}}");
    let label_value = run_docker([
        "volume",
        "inspect",
        "--format",
        format_argument.as_str(),
        volume_name,
    ])?;
    Ok(label_value.trim() == "true")
}

fn volume_mountpoint(volume_name: &str) -> Result<String, DockerError> {
    let mountpoint = run_docker(["volume", "inspect", "--format", "{{.Mountpoint}}", volume_name])?;
    let mountpoint = mountpoint.trim().to_string();
    if mountpoint.starts_with('/') {
        Ok(mountpoint)
    } else {
        Err(DockerError::CommandFailed(format!(
            "volume '{volume_name}' has no usable mountpoint: '{mountpoint}'"
        )))
    }
}

/// Archives a directory with `tar` (entries sorted by name, numeric owners, so
/// an unchanged directory always produces byte-identical output), writing the
/// archive to `destination`. Returns the archive's SHA-256 (lowercase hex) and size.
fn archive_directory(directory: &str, destination: &Path) -> Result<(String, u64), DockerError> {
    let mut tar_process = Command::new("sudo")
        .args(["tar", "--sort=name", "--numeric-owner", "-C", directory, "-cf", "-", "."])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| DockerError::CommandFailed(format!("could not run tar: {error}")))?;
    let mut tar_output = tar_process
        .stdout
        .take()
        .ok_or_else(|| DockerError::CommandFailed("could not read tar output".into()))?;

    let mut destination_file =
        fs::File::create(destination).map_err(io_failure("could not create archive file"))?;
    let mut hasher = Sha256::new();
    let mut size_bytes: u64 = 0;
    let mut buffer = vec![0u8; ARCHIVE_COPY_BUFFER_BYTES];
    loop {
        let bytes_read = tar_output
            .read(&mut buffer)
            .map_err(io_failure("could not read tar output"))?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
        destination_file
            .write_all(&buffer[..bytes_read])
            .map_err(io_failure("could not write archive file"))?;
        size_bytes += bytes_read as u64;
    }

    let finished = tar_process
        .wait_with_output()
        .map_err(|error| DockerError::CommandFailed(format!("tar did not finish: {error}")))?;
    if !finished.status.success() {
        return Err(DockerError::CommandFailed(format!(
            "tar failed: {}",
            String::from_utf8_lossy(&finished.stderr).trim()
        )));
    }
    Ok((format!("{:x}", hasher.finalize()), size_bytes))
}

/// Archives a managed volume's contents into `archive_store`, under a file
/// named by the archive's content hash. Identical content is stored once.
/// Refuses volumes that TemporalTrail does not own.
pub fn capture_volume(volume_name: &str, archive_store: &Path) -> Result<VolumeCapture, DockerError> {
    validate_volume_name(volume_name)?;
    if !is_volume_managed(volume_name)? {
        return Err(DockerError::NotManaged(volume_name.to_string()));
    }
    let mountpoint = volume_mountpoint(volume_name)?;
    fs::create_dir_all(archive_store).map_err(io_failure("could not create archive store"))?;

    let incoming_path = archive_store.join(format!(
        ".incoming-{}.{VOLUME_ARCHIVE_EXTENSION}",
        std::process::id()
    ));
    let (content_hash, size_bytes) = match archive_directory(&mountpoint, &incoming_path) {
        Ok(result) => result,
        Err(error) => {
            let _ = fs::remove_file(&incoming_path);
            return Err(error);
        }
    };

    let archive_path = archive_store.join(format!("{content_hash}.{VOLUME_ARCHIVE_EXTENSION}"));
    let already_stored = archive_path.exists();
    if already_stored {
        let _ = fs::remove_file(&incoming_path);
    } else {
        fs::rename(&incoming_path, &archive_path).map_err(io_failure("could not store archive"))?;
    }
    Ok(VolumeCapture {
        volume_name: volume_name.to_string(),
        content_hash,
        archive_path,
        size_bytes,
        already_stored,
    })
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

    #[test]
    fn snapshot_reference_combines_name_and_tag() {
        assert_eq!(
            snapshot_image_reference("web-1", "checkpoint-3").unwrap(),
            "temporaltrail-snapshot/web-1:checkpoint-3"
        );
    }

    #[test]
    fn rejects_invalid_container_names() {
        for invalid in ["", "Bad Name", "UPPER", "-leading-dash", "a b", "x;y", &"x".repeat(65)] {
            assert!(
                snapshot_image_reference(invalid, "tag").is_err(),
                "should reject container name: {invalid:?}"
            );
        }
    }

    #[test]
    fn rejects_invalid_snapshot_tags() {
        for invalid in ["", "bad tag!", "-dash", ".dot", "a/b", "x;y", &"x".repeat(65)] {
            assert!(
                snapshot_image_reference("web-1", invalid).is_err(),
                "should reject tag: {invalid:?}"
            );
        }
    }

    #[test]
    fn validates_volume_names() {
        for invalid in ["", "bad name", "x;y", "-dash", "a/b", ".hidden", &"x".repeat(65)] {
            assert!(
                validate_volume_name(invalid).is_err(),
                "should reject volume name: {invalid:?}"
            );
        }
        for valid in ["probe-data", "Data_1", "db.v2"] {
            assert!(validate_volume_name(valid).is_ok(), "should accept: {valid:?}");
        }
    }
}