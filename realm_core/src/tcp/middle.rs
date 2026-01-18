use std::io::Result;
use tokio::net::TcpStream;

use super::socket;
use super::plain;
use super::addr_proto;

#[cfg(feature = "hook")]
use super::hook;

#[cfg(feature = "proxy")]
use super::proxy;

#[cfg(feature = "transport")]
use super::transport;

#[cfg(feature = "transport")]
use kaminari::{AsyncAccept, AsyncConnect};

use crate::trick::Ref;
use crate::endpoint::{RemoteAddr, ConnectOpts};
#[allow(unused)]
pub async fn connect_and_relay(
    mut local: TcpStream,
    raddr: Ref<RemoteAddr>,
    conn_opts: Ref<ConnectOpts>,
    extra_raddrs: Ref<Vec<RemoteAddr>>,
) -> Result<()> {
    let ConnectOpts {
        #[cfg(feature = "proxy")]
        proxy_opts,

        #[cfg(feature = "transport")]
        transport,

        #[cfg(feature = "balance")]
        balancer,

        tcp_keepalive,
        remote_addr,
        ..
    } = conn_opts.as_ref();

    // Check if this is dynamic address mode
    if let Some(target_addr) = remote_addr {
        // Client mode: send target address to proxy server
        return client_mode_relay(local, raddr, conn_opts, target_addr).await;
    }

    // Check if this is server mode (empty remote)
    if matches!(raddr.as_ref(), RemoteAddr::DomainName(s, 0) if s.is_empty()) {
        // Server mode: receive target address from client
        return server_mode_relay(local, conn_opts).await;
    }

    // Original static relay mode
    // before connect:
    // - pre-connect hook
    // - load balance
    // ..
    let raddr = {
        #[cfg(feature = "hook")]
        {
            // accept or deny connection.
            #[cfg(feature = "balance")]
            {
                hook::pre_connect_hook(&mut local, raddr.as_ref(), extra_raddrs.as_ref()).await?;
            }

            // accept or deny connection, or select a remote peer.
            #[cfg(not(feature = "balance"))]
            {
                hook::pre_connect_hook(&mut local, raddr.as_ref(), extra_raddrs.as_ref()).await?
            }
        }

        #[cfg(feature = "balance")]
        {
            use realm_lb::{Token, BalanceCtx};
            let token = balancer.next(BalanceCtx {
                src_ip: &local.peer_addr()?.ip(),
            });
            log::debug!("[tcp]select remote peer, token: {:?}", token);
            match token {
                None | Some(Token(0)) => raddr.as_ref(),
                Some(Token(idx)) => &extra_raddrs.as_ref()[idx as usize - 1],
            }
        }

        #[cfg(not(any(feature = "hook", feature = "balance")))]
        raddr.as_ref()
    };

    // connect!
    let mut remote = socket::connect(raddr, conn_opts.as_ref()).await?;
    log::info!("[tcp]{} => {} as {}", local.peer_addr()?, raddr, remote.peer_addr()?);

    // after connected
    // ..
    #[cfg(feature = "proxy")]
    if proxy_opts.enabled() {
        proxy::handle_proxy(&mut local, &mut remote, *proxy_opts).await?;
    }

    // relay
    let res = {
        #[cfg(feature = "transport")]
        {
            if let Some((ac, cc)) = transport {
                transport::run_relay(local, remote, ac, cc).await
            } else {
                plain::run_relay(local, remote).await
            }
        }
        #[cfg(not(feature = "transport"))]
        {
            plain::run_relay(local, remote).await
        }
    };

    // ignore relay error
    if let Err(e) = res {
        log::debug!("[tcp]forward error: {}, ignored", e);
    }

    Ok(())
}

async fn client_mode_relay(
    local: TcpStream,
    raddr: Ref<RemoteAddr>,
    conn_opts: Ref<ConnectOpts>,
    target_addr: &RemoteAddr,
) -> Result<()> {
    // Connect to proxy server
    let remote = socket::connect(raddr.as_ref(), conn_opts.as_ref()).await?;
    log::info!("[tcp][client]{} => {} (proxy)", local.peer_addr()?, raddr.as_ref());

    // For transport mode, handle address exchange after handshake
    #[cfg(feature = "transport")]
    if let Some((ac, cc)) = &conn_opts.as_ref().transport {
        // Perform handshakes
        let mut buf1 = vec![0; realm_io::buf_size()];
        let mut buf2 = vec![0; realm_io::buf_size()];

        let (mut local_stream, mut remote_stream) = futures::try_join!(
            ac.accept(local, &mut buf1),
            cc.connect(remote, &mut buf2)
        )?;

        // Send target address after handshake
        addr_proto::send_target_addr(&mut remote_stream, target_addr).await?;
        let status = addr_proto::read_response(&mut remote_stream).await?;
        if status != 0x00 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "proxy server failed to connect to target",
            ));
        }

        log::info!("[tcp][client]connected to target: {}", target_addr);

        // Relay data
        let buf1 = realm_io::CopyBuffer::new(buf1);
        let buf2 = realm_io::CopyBuffer::new(buf2);
        let res = realm_io::bidi_copy_buf(&mut local_stream, &mut remote_stream, buf1, buf2).await;
        if let Err(e) = res {
            log::debug!("[tcp][client]forward error: {}, ignored", e);
        }
        return Ok(());
    }

    // Without transport, send target address directly
    let mut remote = remote;
    addr_proto::send_target_addr(&mut remote, target_addr).await?;
    let status = addr_proto::read_response(&mut remote).await?;
    if status != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "proxy server failed to connect to target",
        ));
    }

    log::info!("[tcp][client]connected to target: {}", target_addr);

    // Start relay
    let res = plain::run_relay(local, remote).await;
    if let Err(e) = res {
        log::debug!("[tcp][client]forward error: {}, ignored", e);
    }

    Ok(())
}

async fn server_mode_relay(
    local: TcpStream,
    conn_opts: Ref<ConnectOpts>,
) -> Result<()> {
    log::info!("[tcp][server]accepted connection from {}", local.peer_addr()?);

    // For transport mode, handle address exchange after handshake
    #[cfg(feature = "transport")]
    if let Some((ac, _cc)) = &conn_opts.as_ref().transport {
        // Perform handshake
        let mut buf = vec![0; realm_io::buf_size()];
        let mut local_stream = ac.accept(local, &mut buf).await?;

        // Read target address after handshake
        let target_addr = addr_proto::read_target_addr(&mut local_stream).await?;
        log::info!("[tcp][server]target address: {}", target_addr);

        // Connect to target
        let mut remote = match socket::connect(&target_addr, conn_opts.as_ref()).await {
            Ok(r) => {
                addr_proto::send_response(&mut local_stream, 0x00).await?;
                r
            }
            Err(e) => {
                addr_proto::send_response(&mut local_stream, 0x01).await?;
                return Err(e);
            }
        };

        log::info!("[tcp][server]connected to target: {}", target_addr);

        // Relay data
        let buf1 = realm_io::CopyBuffer::new(buf);
        let buf2 = realm_io::CopyBuffer::new(vec![0; realm_io::buf_size()]);
        let res = realm_io::bidi_copy_buf(&mut local_stream, &mut remote, buf1, buf2).await;
        if let Err(e) = res {
            log::debug!("[tcp][server]forward error: {}, ignored", e);
        }
        return Ok(());
    }

    // Without transport, read target address directly
    let mut local = local;
    let target_addr = addr_proto::read_target_addr(&mut local).await?;
    log::info!("[tcp][server]target address: {}", target_addr);

    // Connect to target
    let remote = match socket::connect(&target_addr, conn_opts.as_ref()).await {
        Ok(r) => {
            addr_proto::send_response(&mut local, 0x00).await?;
            r
        }
        Err(e) => {
            addr_proto::send_response(&mut local, 0x01).await?;
            return Err(e);
        }
    };

    log::info!("[tcp][server]connected to target: {}", target_addr);

    // Start relay
    let res = plain::run_relay(local, remote).await;
    if let Err(e) = res {
        log::debug!("[tcp][server]forward error: {}, ignored", e);
    }

    Ok(())
}
