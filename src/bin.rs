use std::env;
use cfg_if::cfg_if;

use realm::cmd;
use realm::conf::{Config, FullConf, LogConf, DnsConf, EndpointInfo};
use realm::ENV_CONFIG;

cfg_if! {
    if #[cfg(feature = "mi-malloc")] {
        use mimalloc::MiMalloc;
        #[global_allocator]
        static GLOBAL: MiMalloc = MiMalloc;
    } else if #[cfg(all(feature = "jemalloc", not(target_env = "msvc")))] {
        use jemallocator::Jemalloc;
        #[global_allocator]
        static GLOBAL: Jemalloc = Jemalloc;
    } else if #[cfg(all(feature = "page-alloc", unix))] {
        use mmap_allocator::MmapAllocator;
        #[global_allocator]
        static GLOBAL: MmapAllocator = MmapAllocator::new();
    }
}

fn main() {
    let conf = 'blk: {
        if let Ok(conf_str) = env::var(ENV_CONFIG) {
            if let Ok(conf) = FullConf::from_conf_str(&conf_str) {
                break 'blk conf;
            }
        };

        use cmd::CmdInput;
        match cmd::scan() {
            CmdInput::Endpoint(ep, opts) => {
                let mut conf = FullConf::default();
                conf.add_endpoint(ep).apply_global_opts().apply_cmd_opts(opts);
                conf
            }
            CmdInput::Config(conf, opts) => {
                let mut conf = FullConf::from_conf_file(&conf);
                conf.apply_global_opts().apply_cmd_opts(opts);
                conf
            }
            CmdInput::None => std::process::exit(0),
        }
    };

    start_from_conf(conf);
}

fn start_from_conf(full: FullConf) {
    let FullConf {
        log: log_conf,
        dns: dns_conf,
        network: network_conf,
        endpoints: endpoints_conf,
        ..
    } = full;

    setup_log(log_conf);
    setup_dns(dns_conf);
    setup_transport();

    let network_info = realm::conf::Config::build(network_conf);
    let auto_bind_all_ips = network_info.auto_bind_all_ips;

    let endpoints: Vec<EndpointInfo> = endpoints_conf
        .into_iter()
        .flat_map(|conf| {
            // Check if listen address is a wildcard (0.0.0.0 or ::)
            let listen_addr = conf.listen.parse::<std::net::SocketAddr>().ok();
            let should_expand = auto_bind_all_ips && listen_addr.map(|addr| {
                addr.ip().is_unspecified()
            }).unwrap_or(false);

            if should_expand {
                // Enumerate all network interfaces and create an endpoint for each IP
                expand_wildcard_endpoint(&conf, listen_addr.unwrap())
            } else {
                vec![Config::build(conf)]
            }
        })
        .inspect(|x| println!("inited: {}", x.endpoint))
        .collect();

    execute(endpoints);
}

fn expand_wildcard_endpoint(conf: &realm::conf::EndpointConf, wildcard_addr: std::net::SocketAddr) -> Vec<EndpointInfo> {
    use if_addrs::get_if_addrs;

    let port = wildcard_addr.port();
    let is_ipv6 = wildcard_addr.is_ipv6();

    match get_if_addrs() {
        Ok(interfaces) => {
            let endpoints: Vec<EndpointInfo> = interfaces
                .into_iter()
                .filter_map(|iface| {
                    let ip = iface.ip();

                    // Filter by IP version
                    if is_ipv6 && !ip.is_ipv6() {
                        return None;
                    }
                    if !is_ipv6 && !ip.is_ipv4() {
                        return None;
                    }

                    // Skip loopback addresses
                    if ip.is_loopback() {
                        return None;
                    }

                    // Create new endpoint config with specific IP
                    let new_addr = std::net::SocketAddr::new(ip, port);
                    let mut new_conf = conf.clone();
                    new_conf.listen = new_addr.to_string();

                    println!("auto-expanded: {} (from {})", new_addr, iface.name);
                    Some(Config::build(new_conf))
                })
                .collect();

            if endpoints.is_empty() {
                println!("warning: no suitable network interfaces found, using original wildcard address");
                vec![Config::build(conf.clone())]
            } else {
                endpoints
            }
        }
        Err(e) => {
            println!("warning: failed to enumerate network interfaces: {}, using original wildcard address", e);
            vec![Config::build(conf.clone())]
        }
    }
}

fn setup_log(log: LogConf) {
    println!("log: {}", &log);

    let (level, output) = log.build();
    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{}[{}][{}]{}",
                chrono::Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
                record.target(),
                record.level(),
                message
            ))
        })
        .level(level)
        .chain(output)
        .apply()
        .unwrap_or_else(|e| panic!("failed to setup logger: {}", &e))
}

fn setup_dns(dns: DnsConf) {
    println!("dns: {}", &dns);

    let (conf, opts) = dns.build();
    realm::core::dns::build_lazy(conf, opts);
}

fn setup_transport() {
    #[cfg(feature = "transport")]
    {
        realm::core::kaminari::install_tls_provider();
    }
}

fn execute(eps: Vec<EndpointInfo>) {
    #[cfg(feature = "multi-thread")]
    {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(run(eps))
    }

    #[cfg(not(feature = "multi-thread"))]
    {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(run(eps))
    }
}

async fn run(endpoints: Vec<EndpointInfo>) {
    use realm::core::tcp::run_tcp;
    use realm::core::udp::run_udp;
    use futures::future::join_all;

    let mut workers = Vec::with_capacity(2 * endpoints.len());

    for EndpointInfo {
        endpoint,
        no_tcp,
        use_udp,
    } in endpoints
    {
        if use_udp {
            workers.push(tokio::spawn(run_udp(endpoint.clone())));
        }

        // Always start TCP unless explicitly disabled
        if !no_tcp {
            workers.push(tokio::spawn(run_tcp(endpoint)));
        }
    }

    workers.shrink_to_fit();

    join_all(workers).await;
}
