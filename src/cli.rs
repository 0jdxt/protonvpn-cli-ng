use crate::{connection, constants::CONFIG_DIR, utils};
use anyhow::Result;
use clap::{clap_app, crate_authors, crate_description, crate_name, crate_version, AppSettings};
use std::fs;

pub async fn cli() -> Result<()> {
    let matches = clap_app!((crate_name!()) =>
        (version: crate_version!())
        (about: crate_description!())
        (author: crate_authors!())
        (settings: &[
            AppSettings::VersionlessSubcommands,
            AppSettings::ArgRequiredElseHelp,
            AppSettings::DeriveDisplayOrder,
            AppSettings::UnifiedHelpMessage,
        ])
        (@subcommand init => (about: "Initialise a ProtonVPN profile"))
        (@subcommand connect =>
            (alias: "c")
            (about: "Connect to a ProtonVPN server")
            (@group connection +required =>
                (@arg    fastest: -f --fastest "Select the fastest ProtonVPN server.")
                (@arg     random: -r --random "Select a random ProtonVPN server.")
                (@arg securecore: --sc "Connect to the fastest Secure-Core server.")
                (@arg        p2p: --p2p "Connect to the fastest torrent server.")
                (@arg        tor: --tor "Connect to the fastest Tor server.")
                (@arg         cc: --cc +takes_value "Connect to the fastest server in a country.")
                (@arg servername: +takes_value "Servername (CH#4, CH-US-1, HK5-Tor)")
            )
            (@arg protocol: -p +takes_value "Determine the protocol (UDP or TCP)")
        )
        (@subcommand reconnect  => (about: "Reconnect to the last server.") (alias: "r"))
        (@subcommand disconnect => (about: "Disconnect the current session.") (alias: "d"))
        (@subcommand status     => (about: "Show connection status.") (alias: "s"))
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

            let wait =
                std::env::var("PVPN_WAIT").map_or(0, |v| u64::from_str_radix(&v, 10).unwrap());
            if wait > 0 {
                utils::wait_for_network(wait).await?;
            }

            let protocol = matches.value_of("protocol").unwrap_or("udp").to_lowercase();

            if let Some(server) = matches.value_of("servername") {
                connection::direct(server, &protocol).await
            } else if matches.is_present("fastest") {
                connection::fastest(&protocol).await
            } else if matches.is_present("random") {
                connection::random_c(&protocol).await
            } else if matches.is_present("p2p") {
                connection::feature_f(utils::Feature::P2P, &protocol).await
            } else if matches.is_present("securecore") {
                connection::feature_f(utils::Feature::SecureCore, &protocol).await
            } else if matches.is_present("tor") {
                connection::feature_f(utils::Feature::Tor, &protocol).await
            } else if let Some(cc) = matches.value_of("cc") {
                connection::country_f(cc, &protocol).await
            } else {
                connection::dialog().await
            }
        }
        ("reconnect", _) => {
            utils::check_root()?;
            utils::check_init(true);
            connection::reconnect().await
        }
        ("disconnect", _) => {
            utils::check_root()?;
            utils::check_init(true);
            connection::disconnect(false)
        }
        ("status", _) => connection::status().await,
        ("configure", _) => {
            utils::check_root()?;
            utils::check_init(false);
            utils::configure_cli();
            Ok(())
        }
        ("refresh", _) => {
            utils::pull_server_data(true).await?;
            utils::make_ovpn_template();
            Ok(())
        }
        ("examples", _) => {
            print_examples();
            Ok(())
        }
        (subcmd, _) => unreachable!("unknown command: {}", subcmd),
    }
}

macro_rules! config_section {
    ($section:expr) => {
        macro_rules! config_user {
            ($key:expr) => {
                config_user!($key, "None")
            };
            ($key:expr, $val:expr) => {
                utils::set_config_value($section, $key, $val)
            };
        }
    };
}

fn init_cli() -> Result<()> {
    fn init_config_file() {
        {
            config_section!("USER");
            config_user!("username");
            config_user!("tier");
            config_user!("default_protocol");
            config_user!("initialized", "0");
            config_user!("dns_leak_protection", "1");
            config_user!("custom_dns");
            config_user!("check_update_interval");
        }
        {
            config_section!("metadata");
            config_user!("last_api_pull", "0");
            config_user!("last_update_check", &utils::time().to_string());
        }
    }

    utils::check_root()?;

    if !CONFIG_DIR.is_dir() {
        fs::create_dir(CONFIG_DIR.as_path())?;
    }
    utils::change_file_owner(CONFIG_DIR.as_path())?;

    if let Some(init) = utils::get_config_value("USER", "initialized") {
        if init != "0" {
            println!("An initialized profile has been found.");
            print!("Are you sure you want to overwite that profile? [y/N]: ");

            let mut input = String::new();
            let res = std::io::stdin().read_line(&mut input);
            if res.is_ok() && input.to_lowercase() != "y" {
                println!("Quitting...");
                std::process::exit(1);
            }

            connection::disconnect(true)?;
        }
    }

    let (terminal_size::Width(term_width), _) = terminal_size::terminal_size().unwrap();
    println!(
        "{:^width$}",
        "[ -- PROTONVPN-CLI INIT -- ]",
        width = term_width as usize,
    );

    // TODO: print init message
    // etc.

    Ok(())
}

#[test]
fn terminal_size() {
    assert!(terminal_size::terminal_size().is_some());
}

fn print_examples() {
    todo!("examples")
}
