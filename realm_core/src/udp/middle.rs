use std::io::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

use super::SockMap;
use super::{socket, batched};

use crate::trick::Ref;
use crate::time::timeoutfut;
use crate::dns::resolve_addr;
use crate::endpoint::{RemoteAddr, ConnectOpts, BindOpts};

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

// Dynamic client mode: prepend target address to each UDP packet
pub async fn run_dynamic_client(
    laddr: SocketAddr,
    proxy_addr: RemoteAddr,
    bind_opts: BindOpts,
    conn_opts: ConnectOpts,
) -> Result<()> {
    let target_addr = conn_opts.remote_addr.as_ref().unwrap();
    let lis = Arc::new(socket::bind(&laddr, bind_opts)?);
    let proxy_resolved = resolve_addr(&proxy_addr).await?.iter().next().unwrap();

    log::info!("[udp][client]forwarding {} -> {} (target: {})", laddr, proxy_resolved, target_addr);

    let sockmap = Arc::new(SockMap::new());
    let mut buf = vec![0u8; 65535];

    loop {
        let (len, client_addr) = lis.recv_from(&mut buf).await?;
        let data = &buf[..len];

        // Get or create connection to proxy
        let proxy_sock = sockmap.find_or_insert(&client_addr, || {
            let s = Arc::new(socket::associate(&proxy_resolved, &conn_opts)?);
            tokio::spawn(recv_from_proxy(lis.clone(), client_addr, s.clone(), conn_opts.associate_timeout, sockmap.clone()));
            log::info!("[udp][client]new association {} => {}", client_addr, proxy_resolved);
            Result::Ok(s)
        })?;

        // Encode target address + data
        let mut packet = Vec::with_capacity(256 + len);
        encode_target_addr(&mut packet, target_addr).await?;
        packet.extend_from_slice(data);

        proxy_sock.send(&packet).await?;
    }
}

// Dynamic server mode: extract target address from each UDP packet
pub async fn run_dynamic_server(
    laddr: SocketAddr,
    bind_opts: BindOpts,
    conn_opts: ConnectOpts,
) -> Result<()> {
    let lis = Arc::new(socket::bind(&laddr, bind_opts)?);
    log::info!("[udp][server]listening on {} (dynamic mode)", laddr);

    let sockmap = Arc::new(SockMap::new());
    let mut buf = vec![0u8; 65535];

    loop {
        let (len, client_addr) = lis.recv_from(&mut buf).await?;
        let data = &buf[..len];

        // Decode target address from packet
        let mut cursor = std::io::Cursor::new(data);
        let target_addr = match decode_target_addr(&mut cursor).await {
            Ok(addr) => addr,
            Err(e) => {
                log::error!("[udp][server]failed to decode target address: {}", e);
                continue;
            }
        };

        let payload_offset = cursor.position() as usize;
        let payload = &data[payload_offset..];

        // Get or create connection to target
        let target_sock = sockmap.find_or_insert(&client_addr, || {
            let target_resolved = futures::executor::block_on(resolve_addr(&target_addr))?.iter().next().unwrap();
            let s = Arc::new(socket::associate(&target_resolved, &conn_opts)?);
            tokio::spawn(recv_from_target(lis.clone(), client_addr, s.clone(), conn_opts.associate_timeout, sockmap.clone()));
            log::info!("[udp][server]new association {} => {}", client_addr, target_addr);
            Result::Ok(s)
        })?;

        target_sock.send(payload).await?;
    }
}

async fn recv_from_proxy(
    lis: Arc<UdpSocket>,
    client_addr: SocketAddr,
    proxy_sock: Arc<UdpSocket>,
    timeout: usize,
    sockmap: Arc<SockMap>,
) {
    let mut buf = vec![0u8; 65535];
    loop {
        match timeoutfut(proxy_sock.recv(&mut buf), timeout).await {
            Err(_) => break,
            Ok(Err(e)) => {
                log::error!("[udp][client]recv error: {}", e);
                break;
            }
            Ok(Ok(len)) => {
                if let Err(e) = lis.send_to(&buf[..len], client_addr).await {
                    log::error!("[udp][client]send error: {}", e);
                    break;
                }
            }
        }
    }
    sockmap.remove(&client_addr);
}

async fn recv_from_target(
    lis: Arc<UdpSocket>,
    client_addr: SocketAddr,
    target_sock: Arc<UdpSocket>,
    timeout: usize,
    sockmap: Arc<SockMap>,
) {
    let mut buf = vec![0u8; 65535];
    loop {
        match timeoutfut(target_sock.recv(&mut buf), timeout).await {
            Err(_) => break,
            Ok(Err(e)) => {
                log::error!("[udp][server]recv error: {}", e);
                break;
            }
            Ok(Ok(len)) => {
                if let Err(e) = lis.send_to(&buf[..len], client_addr).await {
                    log::error!("[udp][server]send error: {}", e);
                    break;
                }
            }
        }
    }
    sockmap.remove(&client_addr);
}

async fn encode_target_addr<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    addr: &RemoteAddr,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    const MAGIC: u16 = 0xAA55;
    const TYPE_IPV4: u8 = 0x01;
    const TYPE_IPV6: u8 = 0x02;
    const TYPE_DOMAIN: u8 = 0x03;

    writer.write_u16(MAGIC).await?;

    match addr {
        RemoteAddr::SocketAddr(SocketAddr::V4(addr)) => {
            writer.write_u8(TYPE_IPV4).await?;
            writer.write_all(&addr.ip().octets()).await?;
            writer.write_u16(addr.port()).await?;
        }
        RemoteAddr::SocketAddr(SocketAddr::V6(addr)) => {
            writer.write_u8(TYPE_IPV6).await?;
            writer.write_all(&addr.ip().octets()).await?;
            writer.write_u16(addr.port()).await?;
        }
        RemoteAddr::DomainName(domain, port) => {
            writer.write_u8(TYPE_DOMAIN).await?;
            writer.write_u8(domain.len() as u8).await?;
            writer.write_all(domain.as_bytes()).await?;
            writer.write_u16(*port).await?;
        }
    }

    Ok(())
}

async fn decode_target_addr<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<RemoteAddr> {
    use tokio::io::AsyncReadExt;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    const MAGIC: u16 = 0xAA55;
    const TYPE_IPV4: u8 = 0x01;
    const TYPE_IPV6: u8 = 0x02;
    const TYPE_DOMAIN: u8 = 0x03;

    let magic = reader.read_u16().await?;
    if magic != MAGIC {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid magic",
        ));
    }

    let addr_type = reader.read_u8().await?;

    match addr_type {
        TYPE_IPV4 => {
            let mut ip_bytes = [0u8; 4];
            reader.read_exact(&mut ip_bytes).await?;
            let port = reader.read_u16().await?;
            Ok(RemoteAddr::SocketAddr(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(ip_bytes)),
                port,
            )))
        }
        TYPE_IPV6 => {
            let mut ip_bytes = [0u8; 16];
            reader.read_exact(&mut ip_bytes).await?;
            let port = reader.read_u16().await?;
            Ok(RemoteAddr::SocketAddr(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(ip_bytes)),
                port,
            )))
        }
        TYPE_DOMAIN => {
            let len = reader.read_u8().await?;
            let mut domain_bytes = vec![0u8; len as usize];
            reader.read_exact(&mut domain_bytes).await?;
            let domain = String::from_utf8(domain_bytes).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid domain")
            })?;
            let port = reader.read_u16().await?;
            Ok(RemoteAddr::DomainName(domain, port))
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unknown address type",
        )),
    }
}
