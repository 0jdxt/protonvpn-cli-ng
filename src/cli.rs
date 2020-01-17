use crate::utils;
use anyhow::Result;
use clap::{clap_app, crate_authors, crate_description, crate_name, crate_version};
use serde_derive::{Deserialize, Serialize};
use std::net::Ipv4Addr;

pub async fn cli() -> Result<()> {
    let matches = clap_app!((crate_name!()) =>
        (version: crate_version!())
        (about: crate_description!())
        (author: crate_authors!())
        (@subcommand init => (about: "Initialise a ProtonVPN profile"))
        (@subcommand connect =>
            (alias: "c")
            (about: "Connect to a ProtonVPN server")
            (@group connection +required =>
                (@arg servername: +takes_value "Servername (CH#4, CH-US-1, HK5-Tor)")
                (@arg    fastest: -f --fastest "Select the fastest ProtonVPN server.")
                (@arg     random: -r --random "Select a random ProtonVPN server.")
                (@arg securecore: --sc "Connect to the fastest Secure-Core server.")
                (@arg        p2p: --p2p "Connect to the fastest torrent server.")
                (@arg        tor: --tor "Connect to the fastest Tor server.")
            )
            (@arg protocol: -p +takes_value "Determine the protocol (UDP or TCP)")
        )
        (@subcommand reconnect  => (alias: "r") (about: "Reconnect to the last server."))
        (@subcommand disconnect => (alias: "d") (about: "Disconnect the current session."))
        (@subcommand status     => (alias: "s") (about: "Show connection status."))
        (@subcommand configure  => (about: "Change ProtonVPN-CLI configuration."))
        (@subcommand refresh    => (about: "Refresh OpenVPN configuration and server data."))
        (@subcommand examples   => (about: "Print some examples."))
    )
    .get_matches();

    match matches.subcommand() {
        ("init", _) => init_cli(),
        ("connect", Some(matches)) => {
            utils::check_root()?;
            utils::check_init(true);

            let wait = std::env::var("PVPN_WAIT")
                .map(|v| u64::from_str_radix(&v, 10))?
                .unwrap_or(0);
            if wait > 0 {
                utils::wait_for_network(wait).await;
            }

            let protocol = matches.value_of("protocol").unwrap_or("udp");

            if let Some(server) = matches.value_of("servername") {
                unimplemented!("server {}", server);
            } else if matches.is_present("fastest") {
                unimplemented!("fastest");
            } else if matches.is_present("random") {
                unimplemented!("random");
            } else if matches.is_present("p2p") {
                unimplemented!("p2p")
            } else if matches.is_present("securecore") {
                unimplemented!("sc")
            } else if matches.is_present("tor") {
                unimplemented!("tor")
            } else {
                unreachable!("no connect targets")
            }
        }
        (subcmd, _) => Ok(println!("{}", subcmd)),
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(non_snake_case)]
struct Config {
    USER: UserConfig,
    metadata: Metadata,
}

#[derive(Debug, Serialize, Deserialize)]
struct UserConfig {
    username: Option<String>,
    tier: Option<u8>,
    default_protocol: Option<String>,
    initialized: u8,
    dns_leak_protection: u8,
    custom_dns: Option<String>,
    check_update_interval: u8,
    killswitch: Option<u8>,
    split_tunnel: Option<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Metadata {
    last_api_pull: u64,
    last_update_check: u64,
    dns_server: Option<Ipv4Addr>,
    resolvconf_hash: Option<u64>,
    connected_server: Option<String>,
    connected_proto: Option<String>,
    connected_time: Option<u64>,
}

fn init_cli() -> Result<()> {
    fn init_config_file() {
        let config = Config {
            USER: UserConfig {
                username: None,
                tier: None,
                default_protocol: None,
                initialized: 0,
                dns_leak_protection: 1,
                custom_dns: None,
                check_update_interval: 3,
                killswitch: None,
                split_tunnel: None,
            },
            metadata: Metadata {
                last_api_pull: 0,
                last_update_check: utils::time(),
                dns_server: None,
                resolvconf_hash: None,
                connected_server: None,
                connected_proto: None,
                connected_time: None,
            },
        };

        // let cfg = fs::read_to_string("/root/.pvpn-cli/pvpn-cli.cfg")
        //     .expect("couldnt read file to string");
        // println!("{}", cfg);

        // let c: Config = toml::from_str(&cfg).expect("couldn parse toml");
        // println!("{:?}", c);
    }

    init_config_file();

    println!("init cli");
    Ok(())
}
