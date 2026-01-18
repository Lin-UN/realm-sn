use std::io::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::SockMap;
use super::{socket, batched};

use crate::trick::Ref;
use crate::time::timeoutfut;
use crate::dns::resolve_addr;
use crate::endpoint::{RemoteAddr, ConnectOpts, BindOpts};

#[cfg(feature = "transport")]
use crate::kaminari::AsyncConnect;

use batched::{Packet, SockAddrStore};
use registry::Registry;
mod registry {
    use super::*;
    type Range = std::ops::Range<u16>;

    pub struct Registry {
        pkts: Box<[Packet]>,
        groups: Vec<Range>,
        cursor: u16,
    }

    impl Registry {
        pub fn new(npkts: usize) -> Self {
            debug_assert!(npkts <= batched::MAX_PACKETS);
            Self {
                pkts: vec![Packet::new(); npkts].into_boxed_slice(),
                groups: Vec::with_capacity(npkts),
                cursor: 0u16,
            }
        }

        pub async fn batched_recv_on(&mut self, sock: &UdpSocket) -> Result<()> {
            let n = batched::recv_some(sock, &mut self.pkts).await?;
            self.cursor = n as u16;
            Ok(())
        }

        pub fn group_by_addr(&mut self) {
            let n = self.cursor as usize;
            self.groups.clear();
            group_by_inner(&mut self.pkts[..n], &mut self.groups, |a, b| a.addr == b.addr);
        }

        pub fn group_iter(&self) -> GroupIter<'_> {
            GroupIter {
                pkts: &self.pkts,
                ranges: self.groups.iter(),
            }
        }

        pub fn iter(&self) -> std::slice::Iter<'_, Packet> {
            self.pkts[..self.cursor as usize].iter()
        }

        pub const fn count(&self) -> usize {
            self.cursor as usize
        }
    }

    use std::slice::Iter;
    use std::iter::Iterator;
    pub struct GroupIter<'a> {
        pkts: &'a [Packet],
        ranges: Iter<'a, Range>,
    }

    impl<'a> Iterator for GroupIter<'a> {
        type Item = &'a [Packet];

        fn next(&mut self) -> Option<Self::Item> {
            self.ranges
                .next()
                .map(|Range { start, end }| &self.pkts[*start as usize..*end as usize])
        }
    }

    fn group_by_inner<T, F>(data: &mut [T], groups: &mut Vec<Range>, eq: F)
    where
        F: Fn(&T, &T) -> bool,
    {
        let maxn = data.len();
        let (mut beg, mut end) = (0, 1);
        while end < maxn {
            // go ahead if addr is same
            if eq(&data[end], &data[beg]) {
                end += 1;
                continue;
            }
            // pick packets afterwards
            let mut probe = end + 1;
            while probe < maxn {
                if eq(&data[probe], &data[beg]) {
                    data.swap(probe, end);
                    end += 1;
                }
                probe += 1;
            }
            groups.push(beg as _..end as _);
            (beg, end) = (end, end + 1);
        }
        groups.push(beg as _..end as _);
    }
}

pub async fn associate_and_relay(
    lis: Ref<UdpSocket>,
    rname: Ref<RemoteAddr>,
    conn_opts: Ref<ConnectOpts>,
    sockmap: Ref<SockMap>,
) -> Result<()> {
    let mut registry = Registry::new(batched::MAX_PACKETS);

    loop {
        registry.batched_recv_on(&lis).await?;
        log::debug!("[udp]entry batched recvfrom[{}]", registry.count());
        let raddr = resolve_addr(&rname).await?.iter().next().unwrap();
        log::debug!("[udp]{} resolved as {}", *rname, raddr);

        registry.group_by_addr();
        for pkts in registry.group_iter() {
            let laddr = pkts[0].addr.clone().into();
            let rsock = sockmap.find_or_insert(&laddr, || {
                let s = Arc::new(socket::associate(&raddr, &conn_opts)?);
                tokio::spawn(send_back(lis, laddr, s.clone(), conn_opts, sockmap));
                log::info!("[udp]new association {} => {} as {}", laddr, *rname, raddr);
                Result::Ok(s)
            })?;
            let raddr: SockAddrStore = raddr.into();
            batched::send_all(&rsock, pkts.iter().map(|x| x.ref_with_addr(&raddr))).await?;
        }
    }
}

async fn send_back(
    lsock: Ref<UdpSocket>,
    laddr: SocketAddr,
    rsock: Arc<UdpSocket>,
    conn_opts: Ref<ConnectOpts>,
    sockmap: Ref<SockMap>,
) {
    let mut registry = Registry::new(batched::MAX_PACKETS);
    let timeout = conn_opts.associate_timeout;
    let laddr_s: SockAddrStore = laddr.into();

    loop {
        match timeoutfut(registry.batched_recv_on(&rsock), timeout).await {
            Err(_) => {
                log::debug!("[udp]rear recvfrom timeout");
                break;
            }
            Ok(Err(e)) => {
                log::error!("[udp]rear recvfrom failed: {}", e);
                break;
            }
            Ok(Ok(())) => {
                log::debug!("[udp]rear batched recvfrom[{}]", registry.count())
            }
        };

        let pkts = registry.iter().map(|pkt| pkt.ref_with_addr(&laddr_s));
        if let Err(e) = batched::send_all(&lsock, pkts).await {
            log::error!("[udp]failed to sendto client{}: {}", &laddr, e);
            break;
        }
    }

    sockmap.remove(&laddr);
    log::debug!("[udp]remove association for {}", &laddr);
}

// Dynamic client mode: UDP over TCP (with TLS support)
pub async fn run_dynamic_client(
    laddr: SocketAddr,
    proxy_addr: RemoteAddr,
    bind_opts: BindOpts,
    conn_opts: ConnectOpts,
) -> Result<()> {
    let target_addr = conn_opts.remote_addr.as_ref().unwrap().clone();
    let lis = Arc::new(socket::bind(&laddr, bind_opts)?);

    log::info!("[udp][client]forwarding {} -> {} (target: {}, over TCP)", laddr, proxy_addr, target_addr);

    type TcpConnMap = std::collections::HashMap<SocketAddr, std::sync::mpsc::SyncSender<Vec<u8>>>;
    let conn_map: Arc<std::sync::Mutex<TcpConnMap>> = Arc::new(std::sync::Mutex::new(TcpConnMap::new()));

    let mut buf = vec![0u8; 65535];

    loop {
        let (len, client_addr) = lis.recv_from(&mut buf).await?;
        let data = &buf[..len];

        // Get or create TCP connection for this UDP client
        let mut map = conn_map.lock().unwrap();
        let tx = match map.get(&client_addr) {
            Some(tx) => tx.clone(),
            None => {
                let (tx, rx) = std::sync::mpsc::sync_channel(100);

                let lis_clone = lis.clone();
                let proxy_addr_clone = proxy_addr.clone();
                let conn_opts_clone = conn_opts.clone();
                let target_addr_clone = target_addr.clone();
                let conn_map_clone = conn_map.clone();

                tokio::spawn(async move {
                    if let Err(e) = handle_tcp_to_proxy(
                        lis_clone,
                        client_addr,
                        proxy_addr_clone,
                        target_addr_clone,
                        conn_opts_clone,
                        rx,
                    ).await {
                        log::error!("[udp][client]TCP connection error for {}: {}", client_addr, e);
                    }
                    conn_map_clone.lock().unwrap().remove(&client_addr);
                });

                map.insert(client_addr, tx.clone());
                tx
            }
        };
        drop(map);

        // Send UDP data through TCP connection (blocking send with backpressure)
        if let Err(e) = tx.send(data.to_vec()) {
            log::error!("[udp][client]failed to send to TCP connection for {}: {}", client_addr, e);
        }
    }
}

async fn handle_tcp_to_proxy(
    lis: Arc<UdpSocket>,
    client_addr: SocketAddr,
    proxy_addr: RemoteAddr,
    target_addr: RemoteAddr,
    conn_opts: ConnectOpts,
    rx: std::sync::mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    // Establish TCP connection to proxy
    let stream = crate::tcp::socket::connect(&proxy_addr, &conn_opts).await?;

    // Apply transport (TLS/WebSocket) if configured
    #[cfg(feature = "transport")]
    let stream = {
        if let Some((_, ref cc)) = conn_opts.transport {
            let mut buf = [0u8; 0];
            cc.connect(stream, &mut buf).await?
        } else {
            use crate::kaminari::mix::MixClientStream;
            MixClientStream::Plain(stream)
        }
    };

    #[cfg(not(feature = "transport"))]
    let stream = stream;

    log::info!("[udp][client]TCP connection established for {} => {}", client_addr, proxy_addr);

    // Split stream into read and write halves
    let (mut reader, mut writer) = tokio::io::split(stream);

    // Send target address first
    crate::tcp::addr_proto::send_target_addr_with_type(&mut writer, &target_addr, crate::tcp::addr_proto::ProtocolType::UdpOverTcp).await?;
    let response = crate::tcp::addr_proto::read_response(&mut reader).await?;
    if response != 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "server rejected target address"));
    }

    log::info!("[udp][client]TCP connection ready for {} => {}", client_addr, proxy_addr);

    // Spawn task to read from TCP and send to UDP client
    let lis_clone = lis.clone();
    tokio::spawn(async move {
        log::debug!("[udp][client]spawn task started for {}", client_addr);
        let mut buf = vec![0u8; 65535];
        loop {
            log::debug!("[udp][client]waiting to read from TCP for {}", client_addr);
            match read_udp_packet(&mut reader, &mut buf).await {
                Ok(len) => {
                    log::debug!("[udp][client]received {} bytes from TCP, sending to UDP client {}", len, client_addr);

                    // Convert IPv4-mapped IPv6 address to IPv4 if needed
                    let target_addr = match client_addr {
                        SocketAddr::V6(v6) => {
                            if let Some(ipv4) = v6.ip().to_ipv4_mapped() {
                                SocketAddr::new(std::net::IpAddr::V4(ipv4), v6.port())
                            } else {
                                client_addr
                            }
                        }
                        _ => client_addr,
                    };

                    if let Err(e) = lis_clone.send_to(&buf[..len], target_addr).await {
                        log::error!("[udp][client]failed to send to UDP client {}: {}", target_addr, e);
                        break;
                    }
                    log::debug!("[udp][client]successfully sent {} bytes to UDP client {}", len, target_addr);
                }
                Err(e) => {
                    log::debug!("[udp][client]TCP read closed for {}: {}", client_addr, e);
                    break;
                }
            }
        }
        log::debug!("[udp][client]spawn task ended for {}", client_addr);
    });

    // Read from channel and send to TCP
    let rx = Arc::new(std::sync::Mutex::new(rx));
    loop {
        let rx_clone = rx.clone();
        let data = match tokio::task::spawn_blocking(move || {
            rx_clone.lock().unwrap().recv()
        }).await {
            Ok(Ok(data)) => data,
            Ok(Err(_)) => {
                log::debug!("[udp][client]channel closed for {}", client_addr);
                break;
            }
            Err(e) => {
                log::error!("[udp][client]spawn_blocking failed: {}", e);
                break;
            }
        };
        log::debug!("[udp][client]sending {} bytes to TCP for {}", data.len(), client_addr);
        if let Err(e) = write_udp_packet(&mut writer, &data).await {
            log::error!("[udp][client]failed to write to TCP: {}", e);
            return Err(e);
        }
    }

    Ok(())
}

// Helper functions for UDP packet framing over TCP
async fn write_udp_packet<W: AsyncWriteExt + Unpin>(writer: &mut W, data: &[u8]) -> Result<()> {
    if data.len() > 65535 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "UDP packet too large"));
    }
    writer.write_u16(data.len() as u16).await?;
    writer.write_all(data).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_udp_packet<R: AsyncReadExt + Unpin>(reader: &mut R, buf: &mut [u8]) -> Result<usize> {
    let len = reader.read_u16().await? as usize;
    if len > buf.len() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "UDP packet too large"));
    }
    reader.read_exact(&mut buf[..len]).await?;
    Ok(len)
}
