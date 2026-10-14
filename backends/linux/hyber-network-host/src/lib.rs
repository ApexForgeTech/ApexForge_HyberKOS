//! Temporary hosted transport adapter. Host socket values never cross this crate boundary.
use hyber_network::{
    Endpoint, HostName, InterfaceInfo, NetworkProvider, Protocol, ProviderError, ProviderSocketId,
    ResolutionInfo, MAX_DATAGRAM_BYTES, MAX_IO_BYTES, MAX_SOCKETS,
};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
static RESOLVERS: AtomicUsize = AtomicUsize::new(0);
const CACHE_SECONDS: u32 = 30;
struct CacheEntry {
    addresses: Vec<IpAddr>,
    expires: Instant,
}
struct ResolverPermit;
impl Drop for ResolverPermit {
    fn drop(&mut self) {
        RESOLVERS.fetch_sub(1, Ordering::SeqCst);
    }
}

enum HostSocket {
    Tcp(TcpStream),
    Udp(UdpSocket),
}
pub struct HostedNetworkProvider {
    sockets: BTreeMap<ProviderSocketId, HostSocket>,
    next: u64,
    timeout: Duration,
    cache: BTreeMap<HostName, CacheEntry>,
}
impl Default for HostedNetworkProvider {
    fn default() -> Self {
        Self {
            sockets: BTreeMap::new(),
            next: 1,
            timeout: Duration::from_secs(5),
            cache: BTreeMap::new(),
        }
    }
}
impl HostedNetworkProvider {
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            timeout: timeout.clamp(Duration::from_millis(1), Duration::from_secs(30)),
            ..Self::default()
        }
    }
    fn map(error: &std::io::Error) -> ProviderError {
        use std::io::ErrorKind::*;
        match error.kind() {
            TimedOut => ProviderError::Timeout,
            ConnectionRefused => ProviderError::Refused,
            NotConnected | BrokenPipe | ConnectionAborted | ConnectionReset => {
                ProviderError::Closed
            }
            WouldBlock => ProviderError::WouldBlock,
            AddrNotAvailable | NotFound => ProviderError::Unreachable,
            _ => ProviderError::Io,
        }
    }

    fn addresses(&mut self, host: &HostName) -> Result<(Vec<IpAddr>, bool), ProviderError> {
        self.cache.retain(|_, value| value.expires > Instant::now());
        if let Some(entry) = self.cache.get(host) {
            return Ok((entry.addresses.clone(), true));
        }
        if RESOLVERS
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < 4).then_some(n + 1)
            })
            .is_err()
        {
            return Err(ProviderError::WouldBlock);
        }
        let permit = ResolverPermit;
        let name = host.as_str().to_owned();
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        // libc resolution cannot be interrupted. Bound both the caller wait
        // and outstanding worker count, including workers whose caller timed out.
        std::thread::Builder::new()
            .name("hyber-resolver".into())
            .spawn(move || {
                let _permit = permit;
                let result = (name.as_str(), 0)
                    .to_socket_addrs()
                    .map_err(|e| Self::map(&e))
                    .and_then(|answers| {
                        let addresses: Vec<_> = answers.take(17).map(|a| a.ip()).collect();
                        if addresses.is_empty() || addresses.len() > 16 {
                            Err(ProviderError::Unreachable)
                        } else {
                            Ok(addresses)
                        }
                    });
                let _ = tx.send(result);
            })
            .map_err(|_| ProviderError::Io)?;
        let addresses = rx
            .recv_timeout(self.timeout)
            .map_err(|_| ProviderError::Timeout)??;
        if self.cache.len() >= 128 {
            self.cache.pop_first();
        }
        self.cache.insert(
            host.clone(),
            CacheEntry {
                addresses: addresses.clone(),
                expires: Instant::now() + Duration::from_secs(CACHE_SECONDS as u64),
            },
        );
        Ok((addresses, false))
    }
}
impl NetworkProvider for HostedNetworkProvider {
    fn wait(
        &mut self,
        id: ProviderSocketId,
        interest: hyber_network::WaitInterest,
        timeout_ms: u32,
    ) -> Result<bool, ProviderError> {
        use std::os::fd::AsRawFd;
        if timeout_ms > 30_000 {
            return Err(ProviderError::Io);
        }
        let socket = self.sockets.get(&id).ok_or(ProviderError::Closed)?;
        let fd = match socket {
            HostSocket::Tcp(s) => s.as_raw_fd(),
            HostSocket::Udp(s) => s.as_raw_fd(),
        };
        let events = match interest {
            hyber_network::WaitInterest::Readable => libc::POLLIN,
            hyber_network::WaitInterest::Writable => libc::POLLOUT,
        };
        let mut descriptor = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
        let result = loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let millis = remaining
                .as_nanos()
                .div_ceil(1_000_000)
                .min(timeout_ms as u128) as i32;
            // The socket remains alive; the pointer addresses one initialized pollfd.
            let result = unsafe { libc::poll(&mut descriptor, 1, millis) };
            if result >= 0 {
                break result;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(Self::map(&error));
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
        };
        if descriptor.revents & libc::POLLNVAL != 0 {
            return Err(ProviderError::Closed);
        }
        Ok(result > 0 && descriptor.revents & (events | libc::POLLERR | libc::POLLHUP) != 0)
    }
    fn resolve(&mut self, host: &HostName) -> Result<ResolutionInfo, ProviderError> {
        let (answers, cached) = self.addresses(host)?;
        let cache_seconds = self
            .cache
            .get(host)
            .map(|e| {
                e.expires
                    .saturating_duration_since(Instant::now())
                    .as_secs() as u32
            })
            .unwrap_or(0);
        Ok(ResolutionInfo {
            host: host.clone(),
            answers: answers.len(),
            cached,
            cache_seconds,
        })
    }
    fn interfaces(&mut self) -> Result<Vec<InterfaceInfo>, ProviderError> {
        Ok(vec![InterfaceInfo {
            name: "host0".into(),
            active: true,
            provider: "host-network".into(),
        }])
    }
    fn connect(
        &mut self,
        protocol: Protocol,
        endpoint: &Endpoint,
    ) -> Result<ProviderSocketId, ProviderError> {
        if endpoint.port == 0 || self.sockets.len() >= MAX_SOCKETS {
            return Err(ProviderError::Io);
        }
        let deadline = Instant::now() + self.timeout;
        let (addresses, _) = self.addresses(&endpoint.host)?;
        let addrs = addresses
            .into_iter()
            .map(|ip| SocketAddr::new(ip, endpoint.port));
        let socket = match protocol {
            Protocol::Tcp => {
                let mut last = ProviderError::Unreachable;
                let mut stream = None;
                for addr in addrs {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(ProviderError::Timeout);
                    }
                    match TcpStream::connect_timeout(&addr, remaining) {
                        Ok(value) => {
                            stream = Some(value);
                            break;
                        }
                        Err(error) => last = Self::map(&error),
                    }
                }
                let s = stream.ok_or(last)?;
                s.set_read_timeout(Some(self.timeout))
                    .map_err(|e| Self::map(&e))?;
                s.set_write_timeout(Some(self.timeout))
                    .map_err(|e| Self::map(&e))?;
                HostSocket::Tcp(s)
            }
            Protocol::Udp => {
                let mut last = ProviderError::Unreachable;
                let mut connected = None;
                for addr in addrs {
                    let bind = if addr.is_ipv4() {
                        "0.0.0.0:0"
                    } else {
                        "[::]:0"
                    };
                    let socket = match UdpSocket::bind(bind) {
                        Ok(socket) => socket,
                        Err(error) => {
                            last = Self::map(&error);
                            continue;
                        }
                    };
                    match socket.connect(addr) {
                        Ok(()) => {
                            connected = Some(socket);
                            break;
                        }
                        Err(error) => last = Self::map(&error),
                    }
                }
                let s = connected.ok_or(last)?;
                s.set_read_timeout(Some(self.timeout))
                    .map_err(|e| Self::map(&e))?;
                s.set_write_timeout(Some(self.timeout))
                    .map_err(|e| Self::map(&e))?;
                HostSocket::Udp(s)
            }
        };
        let id = ProviderSocketId(self.next);
        self.next = self.next.checked_add(1).ok_or(ProviderError::Io)?;
        self.sockets.insert(id, socket);
        Ok(id)
    }
    fn send(&mut self, id: ProviderSocketId, data: &[u8]) -> Result<usize, ProviderError> {
        if data.len() > MAX_IO_BYTES {
            return Err(ProviderError::MessageTooLarge);
        }
        match self.sockets.get_mut(&id).ok_or(ProviderError::Closed)? {
            HostSocket::Tcp(s) => s.write(data).map_err(|e| Self::map(&e)),
            HostSocket::Udp(s) => {
                if data.len() > MAX_DATAGRAM_BYTES {
                    return Err(ProviderError::MessageTooLarge);
                }
                s.send(data).map_err(|e| Self::map(&e))
            }
        }
    }
    fn receive(&mut self, id: ProviderSocketId, limit: usize) -> Result<Vec<u8>, ProviderError> {
        if limit == 0 || limit > MAX_IO_BYTES {
            return Err(ProviderError::MessageTooLarge);
        }
        let socket = self.sockets.get_mut(&id).ok_or(ProviderError::Closed)?;
        let mut data = vec![
            0;
            if matches!(socket, HostSocket::Udp(_)) {
                MAX_IO_BYTES
            } else {
                limit
            }
        ];
        let n = match socket {
            HostSocket::Tcp(s) => s.read(&mut data).map_err(|e| Self::map(&e))?,
            HostSocket::Udp(s) => s.recv(&mut data).map_err(|e| Self::map(&e))?,
        };
        // A too-large datagram is consumed as one unit and reported, never
        // silently returned as a truncated successful message.
        if n > limit {
            return Err(ProviderError::MessageTooLarge);
        }
        data.truncate(n);
        Ok(data)
    }

    fn close(&mut self, id: ProviderSocketId) -> Result<(), ProviderError> {
        self.sockets
            .remove(&id)
            .map(|_| ())
            .ok_or(ProviderError::Closed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn readiness_is_bounded_and_rejects_closed_tokens() {
        use hyber_network::WaitInterest;
        let mut provider = HostedNetworkProvider::default();
        let token = provider
            .connect(Protocol::Udp, &Endpoint::new("localhost", 9).unwrap())
            .unwrap();
        assert!(provider.wait(token, WaitInterest::Writable, 0).unwrap());
        assert!(!provider.wait(token, WaitInterest::Readable, 1).unwrap());
        assert_eq!(
            provider.wait(token, WaitInterest::Readable, 30_001),
            Err(ProviderError::Io)
        );
        provider.close(token).unwrap();
        assert_eq!(
            provider.wait(token, WaitInterest::Readable, 0),
            Err(ProviderError::Closed)
        );
    }

    #[test]
    fn loopback_tcp_is_private_behind_provider_token() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0; 2];
            stream.read_exact(&mut buf).unwrap();
            stream.write_all(&buf).unwrap();
        });
        let endpoint = Endpoint::new("localhost", port).unwrap();
        let mut provider = HostedNetworkProvider::with_timeout(Duration::from_secs(1));
        let token = provider.connect(Protocol::Tcp, &endpoint).unwrap();
        assert_eq!(provider.send(token, b"ok").unwrap(), 2);
        assert_eq!(provider.receive(token, 2).unwrap(), b"ok");
        provider.close(token).unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn udp_empty_datagram_and_oversize_are_not_eof_or_silent_truncation() {
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let port = peer.local_addr().unwrap().port();
        let mut provider = HostedNetworkProvider::with_timeout(Duration::from_millis(100));
        // Pin the deterministic test fixture; production callers cannot supply
        // numeric addresses or alter the private resolver cache.
        let host = HostName::parse("loopback.test").unwrap();
        provider.cache.insert(
            host.clone(),
            CacheEntry {
                addresses: vec!["127.0.0.1".parse().unwrap()],
                expires: Instant::now() + Duration::from_secs(2),
            },
        );
        let token = provider
            .connect(Protocol::Udp, &Endpoint { host, port })
            .unwrap();
        provider.send(token, b"ping").unwrap();
        let (_, addr) = peer.recv_from(&mut [0; 16]).unwrap();
        peer.send_to(b"", addr).unwrap();
        assert_eq!(provider.receive(token, 4).unwrap(), b"");
        peer.send_to(b"oversize", addr).unwrap();
        assert_eq!(
            provider.receive(token, 2),
            Err(ProviderError::MessageTooLarge)
        );
        peer.send_to(b"ok", addr).unwrap();
        assert_eq!(provider.receive(token, 2).unwrap(), b"ok");
        assert!(matches!(
            provider.receive(token, 2),
            Err(ProviderError::Timeout | ProviderError::WouldBlock)
        ));
        provider.close(token).unwrap();
    }

    #[test]
    fn resolver_cache_expires_and_provider_bounds_direct_calls() {
        let mut provider = HostedNetworkProvider::default();
        let host = HostName::parse("localhost").unwrap();
        assert!(!provider.resolve(&host).unwrap().cached);
        assert!(provider.resolve(&host).unwrap().cached);
        provider.cache.get_mut(&host).unwrap().expires = Instant::now();
        assert!(!provider.resolve(&host).unwrap().cached);
        assert_eq!(
            provider.receive(ProviderSocketId(999), usize::MAX),
            Err(ProviderError::MessageTooLarge)
        );
        assert_eq!(
            provider.send(ProviderSocketId(999), &vec![0; MAX_IO_BYTES + 1]),
            Err(ProviderError::MessageTooLarge)
        );
    }
}
