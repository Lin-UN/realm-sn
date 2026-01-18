//! UDP relay entrance.

mod socket;
mod sockmap;
mod middle;
mod batched;

use std::io::Result;

use crate::trick::Ref;
use crate::endpoint::{Endpoint, RemoteAddr};

use sockmap::SockMap;
use middle::associate_and_relay;

/// Launch a udp relay.
pub async fn run_udp(endpoint: Endpoint) -> Result<()> {
    let Endpoint {
        laddr,
        raddr,
        bind_opts,
        conn_opts,
        ..
    } = endpoint;

    // Check if this is dynamic mode (client with remote_addr)
    let is_dynamic_client = conn_opts.remote_addr.is_some();

    // Check if this is dynamic mode (server without remote)
    let is_dynamic_server = matches!(raddr, RemoteAddr::DomainName(ref s, 0) if s.is_empty());

    if is_dynamic_client {
        log::info!("[udp]starting in dynamic client mode");
        return middle::run_dynamic_client(laddr, raddr, bind_opts, conn_opts).await;
    }

    if is_dynamic_server {
        log::info!("[udp]starting in dynamic server mode");
        return middle::run_dynamic_server(laddr, bind_opts, conn_opts).await;
    }

    // Original static mode
    let sockmap = SockMap::new();

    let lis = socket::bind(&laddr, bind_opts).unwrap_or_else(|e| panic!("[udp]failed to bind {}: {}", laddr, e));

    let lis = Ref::new(&lis);
    let raddr = Ref::new(&raddr);
    let conn_opts = Ref::new(&conn_opts);
    let sockmap = Ref::new(&sockmap);
    loop {
        if let Err(e) = associate_and_relay(lis, raddr, conn_opts, sockmap).await {
            log::error!("[udp]error: {}", e);
        }
    }
}
