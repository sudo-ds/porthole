//! Windows service install/uninstall support and the hidden service entrypoint.

#[cfg(not(windows))]
use crate::cli::{ServiceInstallArgs, ServiceRunArgs, ServiceUninstallArgs};
#[cfg(not(windows))]
use anyhow::{bail, Result};

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::{install, run, uninstall};

#[cfg(not(windows))]
pub fn install(_args: ServiceInstallArgs) -> Result<()> {
    bail!("Windows service installation is only available on Windows")
}

#[cfg(not(windows))]
pub fn uninstall(_args: ServiceUninstallArgs) -> Result<()> {
    bail!("Windows service uninstallation is only available on Windows")
}

#[cfg(not(windows))]
pub fn run(_args: ServiceRunArgs) -> Result<()> {
    bail!("Windows service runtime is only available on Windows")
}
