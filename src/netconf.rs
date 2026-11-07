//! Platform-specific interface and route configuration.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
pub use linux::{set_up, warn_if_not_forwarding};
#[cfg(windows)]
pub use windows::{set_up, warn_if_not_forwarding};

#[cfg(not(any(target_os = "linux", windows)))]
compile_error!("cynet currently supports Linux and Windows");

use eyre::Context;
use gotatun::tun::tun;

use crate::config::Config;

/// Creates the TUN device with its name and MTU.
pub fn create_tun(config: &Config) -> eyre::Result<tun::AsyncDevice> {
    let mut tun_config = tun::Configuration::default();
    tun_config.tun_name(&config.name).mtu(config.mtu);

    #[cfg(windows)]
    {
        // Never search the current directory or PATH for a DLL in an elevated process.
        let path = match std::env::var_os("CYNET_WINTUN_DLL") {
            Some(path) => std::path::PathBuf::from(path),
            None => std::env::current_exe()
                .wrap_err("failed to locate cynet.exe")?
                .with_file_name("wintun.dll"),
        };
        eyre::ensure!(
            path.is_absolute(),
            "CYNET_WINTUN_DLL must be an absolute path"
        );
        eyre::ensure!(
            path.is_file(),
            "wintun.dll not found at {}; place the matching Wintun DLL next to cynet.exe \
             or set CYNET_WINTUN_DLL to its absolute path",
            path.display()
        );
        let ipv6 = config.addresses.iter().any(std::net::IpAddr::is_ipv6)
            || config.attached.iter().any(|prefix| prefix.addr().is_ipv6());
        tun_config.platform_config(|platform| {
            platform.wintun_file(path.into_os_string());
            platform.wait_for_interfaces(true, ipv6, std::time::Duration::from_secs(10));
        });
    }

    tun::create_as_async(&tun_config).wrap_err_with(|| {
        format!(
            "failed to create the TUN device {} (run with administrator/root privileges)",
            config.name
        )
    })
}
