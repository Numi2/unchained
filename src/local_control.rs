use anyhow::{bail, Context, Result};
use rand::{rngs::OsRng, RngCore};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::Path;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

pub type ControlCapability = [u8; 32];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedControlMessage<T> {
    pub capability: ControlCapability,
    pub body: T,
}

impl<T> AuthenticatedControlMessage<T> {
    pub fn new(capability: ControlCapability, body: T) -> Self {
        Self { capability, body }
    }
}

pub async fn bind_local_listener(socket_path: &Path, label: &str) -> Result<UnixListener> {
    if let Some(parent) = socket_path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!("failed to create {label} directory at {}", parent.display())
        })?;
    }

    if socket_path.exists() {
        match UnixStream::connect(socket_path).await {
            Ok(_) => {
                bail!("{label} socket already active at {}", socket_path.display());
            }
            Err(_) => {
                fs::remove_file(socket_path).with_context(|| {
                    format!(
                        "failed to remove stale {label} socket at {}",
                        socket_path.display()
                    )
                })?;
            }
        }
    }

    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("failed to bind {label} socket at {}", socket_path.display()))?;
    lock_down_path(socket_path, label)?;
    Ok(listener)
}

pub fn write_capability_file(capability_path: &Path, label: &str) -> Result<ControlCapability> {
    if let Some(parent) = capability_path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create {label} capability directory at {}",
                parent.display()
            )
        })?;
    }
    let mut capability = [0u8; 32];
    OsRng.fill_bytes(&mut capability);
    fs::write(capability_path, capability).with_context(|| {
        format!(
            "failed to write {label} capability at {}",
            capability_path.display()
        )
    })?;
    lock_down_path(capability_path, label)?;
    Ok(capability)
}

pub fn read_capability_file(capability_path: &Path, label: &str) -> Result<ControlCapability> {
    let bytes = fs::read(capability_path).with_context(|| {
        format!(
            "failed to read {label} capability at {}",
            capability_path.display()
        )
    })?;
    if bytes.len() != 32 {
        bail!(
            "{label} capability at {} has invalid length {}",
            capability_path.display(),
            bytes.len()
        );
    }
    let mut capability = [0u8; 32];
    capability.copy_from_slice(&bytes);
    Ok(capability)
}

pub fn remove_local_artifacts(socket_path: &Path, capability_path: &Path) {
    let _ = fs::remove_file(socket_path);
    let _ = fs::remove_file(capability_path);
}

pub fn verify_capability(
    expected: &ControlCapability,
    presented: &ControlCapability,
    label: &str,
) -> Result<()> {
    if bool::from(expected.ct_eq(presented)) {
        Ok(())
    } else {
        bail!("unauthorized {label} request")
    }
}

pub fn write_sync_frame<T: Serialize>(
    stream: &mut StdUnixStream,
    value: &T,
    label: &str,
) -> Result<()> {
    let bytes = bincode::serialize(value).with_context(|| format!("failed to encode {label}"))?;
    let len = u32::try_from(bytes.len()).map_err(|_| anyhow::anyhow!("{label} frame too large"))?;
    stream
        .write_all(&len.to_le_bytes())
        .with_context(|| format!("failed to write {label} length"))?;
    stream
        .write_all(&bytes)
        .with_context(|| format!("failed to write {label} body"))?;
    Ok(())
}

pub fn read_sync_frame<T: DeserializeOwned>(stream: &mut StdUnixStream, label: &str) -> Result<T> {
    let mut len_bytes = [0u8; 4];
    stream
        .read_exact(&mut len_bytes)
        .with_context(|| format!("failed to read {label} length"))?;
    let frame_len = u32::from_le_bytes(len_bytes) as usize;
    let mut frame = vec![0u8; frame_len];
    stream
        .read_exact(&mut frame)
        .with_context(|| format!("failed to read {label} body"))?;
    bincode::deserialize(&frame).with_context(|| format!("failed to decode {label}"))
}

pub async fn write_async_frame<T: Serialize, W: AsyncWrite + Unpin>(
    writer: &mut W,
    value: &T,
    label: &str,
) -> Result<()> {
    let bytes = bincode::serialize(value).with_context(|| format!("failed to encode {label}"))?;
    let len = u32::try_from(bytes.len()).map_err(|_| anyhow::anyhow!("{label} frame too large"))?;
    writer
        .write_all(&len.to_le_bytes())
        .await
        .with_context(|| format!("failed to write {label} length"))?;
    writer
        .write_all(&bytes)
        .await
        .with_context(|| format!("failed to write {label} body"))?;
    Ok(())
}

pub async fn read_async_frame<T: DeserializeOwned, R: AsyncRead + Unpin>(
    reader: &mut R,
    label: &str,
) -> Result<Option<T>> {
    let mut len_bytes = [0u8; 4];
    match reader.read_exact(&mut len_bytes).await {
        Ok(_) => {}
        Err(err) if err.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err).with_context(|| format!("failed to read {label} length")),
    }
    let frame_len = u32::from_le_bytes(len_bytes) as usize;
    let mut frame = vec![0u8; frame_len];
    reader
        .read_exact(&mut frame)
        .await
        .with_context(|| format!("failed to read {label} body"))?;
    let decoded =
        bincode::deserialize(&frame).with_context(|| format!("failed to decode {label}"))?;
    Ok(Some(decoded))
}

fn lock_down_path(path: &Path, label: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to lock down {label} path at {}", path.display()))?;
    }
    Ok(())
}
