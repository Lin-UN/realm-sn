use crate::endpoint::RemoteAddr;
use std::io::Result;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAGIC: u16 = 0xAA55;
const TYPE_IPV4: u8 = 0x01;
const TYPE_IPV6: u8 = 0x02;
const TYPE_DOMAIN: u8 = 0x03;

pub async fn send_target_addr<S>(stream: &mut S, addr: &RemoteAddr) -> Result<()>
where
    S: AsyncWriteExt + Unpin,
{
    stream.write_u16(MAGIC).await?;

    match addr {
        RemoteAddr::SocketAddr(SocketAddr::V4(addr)) => {
            stream.write_u8(TYPE_IPV4).await?;
            stream.write_all(&addr.ip().octets()).await?;
            stream.write_u16(addr.port()).await?;
        }
        RemoteAddr::SocketAddr(SocketAddr::V6(addr)) => {
            stream.write_u8(TYPE_IPV6).await?;
            stream.write_all(&addr.ip().octets()).await?;
            stream.write_u16(addr.port()).await?;
        }
        RemoteAddr::DomainName(domain, port) => {
            stream.write_u8(TYPE_DOMAIN).await?;
            stream.write_u8(domain.len() as u8).await?;
            stream.write_all(domain.as_bytes()).await?;
            stream.write_u16(*port).await?;
        }
    }

    stream.flush().await?;
    Ok(())
}

pub async fn read_target_addr<S>(stream: &mut S) -> Result<RemoteAddr>
where
    S: AsyncReadExt + Unpin,
{
    let magic = stream.read_u16().await?;
    if magic != MAGIC {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid protocol magic",
        ));
    }

    let addr_type = stream.read_u8().await?;

    match addr_type {
        TYPE_IPV4 => {
            let mut ip_bytes = [0u8; 4];
            stream.read_exact(&mut ip_bytes).await?;
            let port = stream.read_u16().await?;
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip_bytes)), port);
            Ok(RemoteAddr::SocketAddr(addr))
        }
        TYPE_IPV6 => {
            let mut ip_bytes = [0u8; 16];
            stream.read_exact(&mut ip_bytes).await?;
            let port = stream.read_u16().await?;
            let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip_bytes)), port);
            Ok(RemoteAddr::SocketAddr(addr))
        }
        TYPE_DOMAIN => {
            let len = stream.read_u8().await?;
            let mut domain_bytes = vec![0u8; len as usize];
            stream.read_exact(&mut domain_bytes).await?;
            let domain = String::from_utf8(domain_bytes).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid domain name")
            })?;
            let port = stream.read_u16().await?;
            Ok(RemoteAddr::DomainName(domain, port))
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unknown address type",
        )),
    }
}

pub async fn send_response<S>(stream: &mut S, status: u8) -> Result<()>
where
    S: AsyncWriteExt + Unpin,
{
    stream.write_u8(status).await?;
    stream.flush().await?;
    Ok(())
}

pub async fn read_response<S>(stream: &mut S) -> Result<u8>
where
    S: AsyncReadExt + Unpin,
{
    Ok(stream.read_u8().await?)
}
