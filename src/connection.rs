use crate::constants::{
    IP6TABLES_BACKUP, IPTABLES_BACKUP, IPV6_BACKUP, OVPN_FILE, OVPN_LOG_FILE, PASSFILE,
    RESOLVCONF_BACKUP, TEMPLATE_FILE,
};
use crate::utils::{self, Feature};
use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use maplit::hashmap;
use rand::{self, seq::SliceRandom};
use regex::Regex;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::process::Command;

pub(crate) async fn dialog() -> Result<()> {
    println!("dialog");
    unimplemented!()
}

pub(crate) async fn random_c(protocol: &str) -> Result<()> {
    let servers = utils::get_servers();
    let servername = servers.choose(&mut rand::thread_rng()).unwrap();
    openvpn_connect(&servername.name, protocol).await
}

pub(crate) async fn fastest(protocol: &str) -> Result<()> {
    disconnect(true)?;
    utils::pull_server_data(true).await?;

    let servers = utils::get_servers();
    let mut pool = servers
        .into_iter()
        .filter(|s| ![Feature::SecureCore, Feature::Tor].contains(&s.features))
        .collect::<Vec<_>>();
    let fastest_server = utils::get_fastest_server(&mut pool);
    openvpn_connect(&fastest_server.name, protocol).await
}

pub(crate) async fn country_f(country_code: &str, protocol: &str) -> Result<()> {
    disconnect(true)?;
    utils::pull_server_data(true).await?;
    let servers = utils::get_servers();
    let mut pool = servers
        .into_iter()
        .filter(|s| {
            ![Feature::SecureCore, Feature::Tor].contains(&s.features)
                && s.exit_country == country_code
        })
        .collect::<Vec<_>>();

    let fastest_server = utils::get_fastest_server(&mut pool);
    openvpn_connect(&fastest_server.name, protocol).await
}

pub(crate) async fn feature_f(feature: Feature, protocol: &str) -> Result<()> {
    disconnect(true)?;
    utils::pull_server_data(true).await?;
    let servers = utils::get_servers();
    let mut pool = servers
        .into_iter()
        .filter(|s| s.features == feature)
        .collect::<Vec<_>>();

    let fastest_server = utils::get_fastest_server(&mut pool);
    openvpn_connect(&fastest_server.name, protocol).await
}

pub(crate) async fn direct(input: &str, protocol: &str) -> Result<()> {
    lazy_static! {
        static ref RE_SHORT: Regex = Regex::new(r#"^((\w\w)(-|#)?(\d{1,3})-?(TOR)?)$"#).unwrap();
        static ref RE_LONG: Regex =
            Regex::new(r#"^(((\w\w)(-|#)?([A-Z]{2}|FREE))(-|#)?(\d{1,3})-?(TOR)?)$"#).unwrap();
    }

    utils::pull_server_data(true).await?;

    let input = input.to_uppercase();
    let servername = if let Some(caps) = RE_SHORT.captures(&input) {
        println!("short: {:?}", caps);

        let country_code = caps.get(2).map_or("", |m| m.as_str());
        let number = caps.get(4).map_or("", |m| m.as_str());

        let mut servername = format!("{}#{}", country_code, number);
        if let Some(tor) = caps.get(5) {
            servername.push('-');
            servername.push_str(tor.as_str());
        }
        Ok(servername)
    } else if let Some(caps) = RE_LONG.captures(&input) {
        println!("long: {:?}", caps);

        let country_code = caps.get(3).map_or("", |m| m.as_str());
        let country_code2 = caps.get(5).map_or("", |m| m.as_str());
        let number = caps.get(7).map_or("", |m| m.as_str());

        let mut servername = format!("{}-{}#{}", country_code, country_code2, number);
        if let Some(tor) = caps.get(8) {
            servername.push('-');
            servername.push_str(tor.as_str());
        }
        Ok(servername)
    } else {
        Err(anyhow!("invalid server name: {}", input))
    }?;

    // TODO: check servername in servers.
    let _servers = utils::get_servers();
    openvpn_connect(&servername, protocol).await
}

pub(crate) async fn reconnect() -> Result<()> {
    let servername = match utils::get_config_value("metadata", "connected_server") {
        Some(server) => Ok(server),
        None => Err(anyhow!("No previous connection found")),
    }?;
    let protocol = match utils::get_config_value("metadata", "connected_proto") {
        Some(proto) => Ok(proto),
        None => Err(anyhow!("no previous connection found")),
    }?;

    openvpn_connect(&servername, &protocol).await
}

pub(crate) fn disconnect(passed: bool) -> Result<()> {
    if utils::is_connected()? {
        if passed {
            eprintln!("There is already a VPN connection running.");
            eprintln!("Terminating previous connection...");
        }

        // run pkill regardless
        let out = Command::new("pkill").arg("openvpn").output()?;
        println!("openvpn pid: {:?}", out);
        std::thread::sleep(std::time::Duration::from_millis(500));

        let timer_start = utils::time();
        loop {
            if !utils::is_connected()? {
                break;
            }

            if utils::time() - timer_start <= 5 {
                let out = Command::new("pkill").arg("openvpn").output()?;
                println!("{:?},", out);
                std::thread::sleep(std::time::Duration::from_millis(200));
            } else {
                let _ = Command::new("pkill").arg("-9").arg("openvpn").output()?;
                break;
            }
        }

        if utils::is_connected()? {
            return Err(anyhow!("Could not terminate OpenVPN process"));
        } else {
            manage_dns(&DnsMode::Restore, None)?;
            manage_ipv6(&Ipv6Mode::Restore);
            manage_killswitch(&KillSwitchMode::Restore, None, None);
            if !passed {
                println!("Disconnected.");
            }
        }
    } else {
        if !passed {
            println!("No connection found.");
        }
        manage_dns(&DnsMode::Restore, None)?;
        manage_ipv6(&Ipv6Mode::Restore);
        manage_killswitch(&KillSwitchMode::Restore, None, None);
    }
    Ok(())
}

pub(crate) async fn status() -> Result<()> {
    utils::check_init();

    if !utils::is_connected()? {
        println!("Status:     Disconnected");
        if IPTABLES_BACKUP.is_file() {
            eprintln!("[!] Kill Switch is currently active");
        } else {
            let (ip, isp) = utils::get_ip_info().await?;
            println!("{:<12}{}\n{:<12}{}", "IP:", ip, "ISP:", isp);
        }
        return Ok(());
    }

    utils::pull_server_data(false).await?;

    macro_rules! key_error {
        ($value:expr) => {
            match utils::get_config_value("metadata", $value) {
                Some(value) => value,
                None => anyhow::bail!("It looks like there was never a connection: {}", $value),
            };
        };
    }

    let connected_server = key_error!("connected_server");
    let connected_protocol = key_error!("connected_proto");
    let dns_server = key_error!("dns_server");

    let ping = Command::new("ping")
        .args(&["-c", "1", &dns_server])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .status()?;

    if !ping.success() {
        println!("[!] Could not reach the VPN server");
        println!("[!] You may want to reconnect with 'protonvpn reconnect'");

        anyhow::bail!("Could not reach VPN server");
    }

    let servers = utils::get_servers();
    let (ip, _isp) = utils::get_ip_info().await?;

    let connected_server = utils::get_server_value(&connected_server, &servers).unwrap();
    let country_code = &connected_server.exit_country;
    let country = utils::get_country_name(country_code);
    let city = &connected_server.city;
    let load = &connected_server.load;
    let feature = &connected_server.features;
    let last_connect =
        utils::get_config_value("metadata", "connected_time").expect("no connected_time");
    let connection_time =
        utils::time() - u64::from_str_radix(&last_connect, 10).expect("time to u64");

    let killswitch_status = if IPTABLES_BACKUP.is_file() {
        "Enabled"
    } else {
        "Disabled"
    };
    let connection_time = chrono::Duration::seconds(connection_time as i64);

    macro_rules! status_line {
        ($title:expr, $val:expr) => {
            let mut s = stringify!($title).to_string();
            s.push(':');
            println!("{:<14}{}", s, $val);
        };
    }

    status_line!(Status, "Connected");
    status_line!(Time, connection_time);
    status_line!(IP, ip);
    status_line!(Server, connected_server.name);
    status_line!(Features, feature);
    status_line!(Protocol, connected_protocol);
    status_line!(KillSwitch, killswitch_status);
    status_line!(Country, country);
    status_line!(City, city.clone().unwrap_or_else(|| "None".to_string()));
    status_line!(Load, load);

    Ok(())
}

pub(crate) async fn openvpn_connect(servername: &str, protocol: &str) -> Result<()> {
    let protocol = &protocol.to_lowercase()[..];
    let port = hashmap! {
        "udp" => 1194,
        "tcp" => 443,
    };
    std::fs::copy(TEMPLATE_FILE.as_path(), OVPN_FILE.as_path())?;
    println!("{:?} -> {:?}", TEMPLATE_FILE.as_path(), OVPN_FILE.as_path());

    let servers = utils::get_servers();
    let subs = &utils::get_server_value(servername, &servers)
        .unwrap()
        .servers;
    let ip_list = subs.iter().map(|s| &s.entry_ip).collect::<Vec<_>>();

    let mut config = format!("\n\nproto {}\n", protocol);
    for &ip in ip_list {
        config.push_str(&format!("remote {} {}", ip, port.get(&protocol).unwrap()))
    }
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(OVPN_FILE.as_path())?;
    file.write_all(config.as_bytes())?;

    disconnect(true)?;

    let (old_ip, _) = utils::get_ip_info().await?;
    println!(
        "Connecting to {} via {}...",
        servername,
        protocol.to_uppercase()
    );

    let _ = Command::new("openvpn")
        .args(&[
            "--config",
            OVPN_FILE.to_str().unwrap(),
            "--auth-user-pass",
            PASSFILE.to_str().unwrap(),
        ])
        .stdout(File::open(OVPN_LOG_FILE.as_path())?)
        .stderr(std::process::Stdio::inherit())
        .spawn()?;

    let mut file = File::open(OVPN_LOG_FILE.as_path())?;
    let time_start = utils::time();
    loop {
        let contents = {
            let mut buf = Vec::with_capacity(1000);
            file.read_to_end(&mut buf)?;
            file.seek(SeekFrom::Start(0))?;
            &String::from_utf8(buf)?[..]
        };

        if contents.contains("Initialization Sequence Complete") {
            lazy_static! {
                static ref DNS_DHCP_REGEX: Regex =
                    Regex::new(r#"(dhcp-option DNS )(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"#)
                        .unwrap();
            }
            if let Some(caps) = DNS_DHCP_REGEX.captures(contents) {
                let dns_server = caps.get(2).map_or("", |m| m.as_str());
                utils::set_config_value("metadata", "dns_server", dns_server);
                manage_dns(&DnsMode::LeakProtection, Some(dns_server))?;
            } else {
                println!("[!] Could not enable DNS Leak Protection!");
                println!("[!] Make sure you are protected!")
            }
            manage_ipv6(&Ipv6Mode::Disable);
            manage_killswitch(
                &KillSwitchMode::Enable,
                Some(protocol),
                Some(port.get(protocol).unwrap()),
            );

            let (new_ip, _) = utils::get_ip_info().await?;
            println!("{} {}", new_ip, old_ip);
            if old_ip == new_ip {
                println!("[!] Connection failed. Reverting all changes...");
                disconnect(true)?;
            }
            println!("Connected!");
            break;
        } else if contents.contains("AUTH_FAILED") {
            println!("[!] Authentication failed.");
            println!("[!] Please make sure that your username and password are correct.");
            return Err(anyhow!("auth failed"));
        } else if utils::time() - time_start >= 45 {
            println!("Connection timed out after 45 seconds");
            return Err(anyhow!("timeout"));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    utils::set_config_value("metadata", "connected_server", servername);
    utils::set_config_value("metadata", "connected_proto", protocol);
    utils::set_config_value("metadata", "connection_time", &utils::time().to_string());

    utils::check_update();

    Ok(())
}

#[derive(Debug)]
enum DnsMode {
    LeakProtection,
    Restore,
}
fn manage_dns(mode: &DnsMode, dns_server: Option<&str>) -> Result<()> {
    let backup = RESOLVCONF_BACKUP.as_path();
    let resolvconf = std::path::Path::new("/etc/resolv.conf");
    match mode {
        DnsMode::LeakProtection => {
            let mut dns_server = match dns_server {
                Some(s) => s,
                None => return Err(anyhow!("Enabling leak_protection requires a dns_server")),
            };

            if backup.is_file() {
                manage_dns(&DnsMode::Restore, None)?;
            }

            let leak_protection = utils::get_config_value("USER", "dns_leak_protection").unwrap();
            let custom_dns = utils::get_config_value("USER", "custom_dns").unwrap();
            if leak_protection != "0" {
                if custom_dns == "None" {
                    println!("DNS Leak protection is disabled");
                    return Ok(());
                } else {
                    dns_server = &custom_dns;
                    println!("using custom dns");
                }
            }

            if dns_server.is_empty() {
                return Err(anyhow!("No DNS Server provided"));
            }

            fs::copy(resolvconf, backup)?;
            lazy_static! {
                static ref DNS_REGEX: Regex = Regex::new(r#"^nameserver .*$"#).unwrap();
            }

            let clean_conf = BufReader::new(File::open(resolvconf)?)
                .lines()
                .filter_map(Result::ok)
                .filter(|ln| !DNS_REGEX.is_match(ln))
                .collect::<Vec<_>>()
                .join("\n");
            fs::write(resolvconf, clean_conf)?;

            let dns_parts = dns_server.split_whitespace();
            let mut output = String::from("# ProtonVPN DNS Servers. Managed by ProtonVPN-CLI.\n");
            for part in dns_parts.take(3) {
                let ln = format!("nameserver {}\n", part);
                output.push_str(&ln);
            }
            fs::write(resolvconf, output)?;

            let contents = fs::read(resolvconf)?;
            let filehash = crc::crc32::checksum_ieee(&contents).to_string();
            utils::set_config_value("metadata", "resolvconf_hash", &filehash);
        }
        DnsMode::Restore => {
            if backup.is_file() {
                let old_hash = utils::get_config_value("metadata", "resolvconf_hash").unwrap();

                let contents = fs::read(resolvconf)?;
                let new_hash = crc::crc32::checksum_ieee(&contents).to_string();
                if old_hash == new_hash {
                    std::fs::copy(&backup, &resolvconf)?;
                } else {
                    // NOTE: resolv.conf has changed
                }

                std::fs::remove_file(backup)?;
            } else {
                // NOTE: no backup file found
            }
        }
    }
    Ok(())
}

enum Ipv6Mode {
    Disable,
    Restore,
    LegacyRestore,
}
fn manage_ipv6(mode: &Ipv6Mode) {
    let ipv6_backup = IPV6_BACKUP.as_path();
    let ip6tables_backup = IP6TABLES_BACKUP.as_path();

    match mode {
        Ipv6Mode::Disable => {
            if ipv6_backup.is_file() {
                manage_ipv6(&Ipv6Mode::LegacyRestore);
            }

            if ip6tables_backup.is_file() {
                manage_ipv6(&Ipv6Mode::Restore);
            }

            let ip6tables_rules = {
                let output = Command::new("ip6tables-save")
                    .output()
                    .expect("ip6tables-save");

                String::from_utf8(output.stdout).expect("ouput to string")
            };

            fs::write(
                ip6tables_backup,
                if ip6tables_rules.contains("COMMIT") {
                    ip6tables_rules
                } else {
                    [
                        "*filter",
                        ":INPUT ACCEPT",
                        ":FORWARD ACCEPT",
                        ":OUTPUT ACCEPT",
                        "COMMIT",
                    ]
                    .join("\n")
                },
            )
            .expect("writing to ip6tables_backup");

            let default_nic = utils::get_default_nic().expect("getting nic");
            let commands = &[
                ["-A", "INPUT", "-i", &default_nic, "-j", "DROP"],
                ["-A", "OUTPUT", "-o", &default_nic, "-j", "DROP"],
            ];
            for command in commands {
                Command::new("ip6tables")
                    .args(command)
                    .output()
                    .expect("ip6tables");
            }
        }
        Ipv6Mode::Restore => {
            if ipv6_backup.is_file() {
                manage_ipv6(&Ipv6Mode::LegacyRestore);
            }

            if ip6tables_backup.is_file() {
                let file =
                    fs::File::open(&ip6tables_backup).expect("couldnt open ip6tables backup");
                Command::new("ip6tables-restore")
                    .stdin(file)
                    .output()
                    .expect("restore ip6tables");
                fs::remove_file(ip6tables_backup).expect("couldnt delete ip6tables backup");
            } else {
                // NOTE: no backup found
            }
        }
        Ipv6Mode::LegacyRestore => todo!("tried to legacy restore Ipv6"),
    }
}

#[derive(Debug)]
enum KillSwitchMode {
    Restore,
    Enable,
}
fn manage_killswitch(mode: &KillSwitchMode, _protocol: Option<&str>, _port: Option<&u32>) {
    let backup = IPTABLES_BACKUP.as_path();
    match mode {
        KillSwitchMode::Restore => {
            if backup.is_file() {
                let file = fs::File::open(backup).expect("couldnt open backup file");
                Command::new("iptables-restore")
                    .stdin(file)
                    .output()
                    .expect("couldnt restore iptables");
                fs::remove_file(backup).expect("failed to delete ip backup");
            } else {
                println!("no backup file");
            }
        }
        KillSwitchMode::Enable => {
            let killswitch = utils::get_config_value("USER", "killswitch").unwrap();
            if killswitch == "0" {
                return;
            }
            todo!("enable killswitch")
        }
    }
}
