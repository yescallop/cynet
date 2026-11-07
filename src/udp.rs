//! UDP transport configuration shared by the daemon and integration tests.

#[cfg(not(windows))]
pub use gotatun::udp::socket::UdpSocketFactory;

#[cfg(windows)]
pub use windows::UdpSocketFactory;

#[cfg(windows)]
mod windows {
    use std::{io, net::Ipv4Addr, os::windows::io::AsRawSocket, ptr};

    use gotatun::udp::{UdpTransportFactory, UdpTransportFactoryParams, socket::UdpSocket};
    use windows_sys::Win32::Networking::WinSock::{
        SIO_UDP_CONNRESET, SIO_UDP_NETRESET, WSAEADDRNOTAVAIL, WSAEAFNOSUPPORT, WSAGetLastError,
        WSAIoctl,
    };

    /// The default gotatun UDP transport with asynchronous ICMP reset reporting disabled.
    /// An unreachable peer must not tear down the socket shared by every other peer.
    #[derive(Debug, Default)]
    pub struct UdpSocketFactory {
        /// Optional receive buffer size, in bytes.
        pub recv_buffer_size: Option<usize>,
        /// Optional send buffer size, in bytes.
        pub send_buffer_size: Option<usize>,
    }

    impl UdpTransportFactory for UdpSocketFactory {
        type Send = UdpSocket;
        type Recv = UdpSocket;

        async fn bind(
            &mut self,
            params: &UdpTransportFactoryParams,
        ) -> io::Result<(Self::Send, Self::Recv)> {
            let mut factory = gotatun::udp::socket::UdpSocketFactory {
                recv_buffer_size: self.recv_buffer_size,
                send_buffer_size: self.send_buffer_size,
            };
            let (tx, rx) = match factory.bind(params).await {
                Ok(sockets) => sockets,
                Err(error)
                    if params.addr.is_none()
                        && matches!(
                            error.raw_os_error(),
                            Some(WSAEAFNOSUPPORT | WSAEADDRNOTAVAIL)
                        ) =>
                {
                    tracing::warn!("IPv6 UDP sockets are unavailable; continuing with IPv4-only");
                    let params = UdpTransportFactoryParams {
                        addr: Some(Ipv4Addr::UNSPECIFIED.into()),
                        ..params.clone()
                    };
                    factory.bind(&params).await?
                }
                Err(error) => return Err(error),
            };
            let socket = tx.socket().as_raw_socket() as usize;
            let disabled: i32 = 0;
            for control in [SIO_UDP_CONNRESET, SIO_UDP_NETRESET] {
                let mut returned = 0;
                // SAFETY: this synchronous IOCTL only borrows a BOOL and a writable byte count.
                let result = unsafe {
                    WSAIoctl(
                        socket,
                        control,
                        (&disabled as *const i32).cast(),
                        std::mem::size_of_val(&disabled) as u32,
                        ptr::null_mut(),
                        0,
                        &mut returned,
                        ptr::null_mut(),
                        None,
                    )
                };
                if result != 0 {
                    // SAFETY: WSAGetLastError takes no arguments and reports the preceding call.
                    return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
                }
            }
            Ok((tx, rx))
        }
    }
}
