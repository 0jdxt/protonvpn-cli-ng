use crate::constants::{CONFIG_FILE, COUNTRY_CODES, SERVER_INFO_FILE};
use crate::utils;

use anyhow::{anyhow, Result};
use hyper::body::Bytes;
use hyper::{Body, Client, Request, Uri};
use hyper_tls::HttpsConnector;
use ini::Ini;
use lazy_static::lazy_static;
use nix::unistd::{self, Gid, Uid};
use rand::seq::SliceRandom;
use rand::thread_rng;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

use std::env;
use std::fs;
use std::net::Ipv4Addr;
use std::os::linux::fs::MetadataExt;
use std::process::Command;
use std::{
    fmt::Display,
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) async fn call_api(endpoint: &str) -> Result<Bytes> {
    let url = Uri::builder()
        .scheme("https")
        .authority("api.protonvpn.ch")
        .path_and_query(endpoint)
        .build()?;

    let req = Request::get(url)
        .header("x-pm-appversion", "Other")
        .header("x-pm-apiversion", "3")
        .header("Accept", "application/vnd.protonmail.v1+json")
        .body(Body::empty())?;

    let body = Client::builder()
        .build(HttpsConnector::new())
        .request(req)
        .await?
        .into_body();

    Ok(hyper::body::to_bytes(body).await?)
}

pub(crate) fn time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_secs()
}

/// default: false
pub(crate) async fn pull_server_data(force: bool) -> Result<()> {
    let last_pull = get_config_value("metadata", "last_api_pull").unwrap();

    // if not force, only pull if at least 15 mins since last_pull
    if force || time() - u64::from_str_radix(&last_pull, 10)? > 900 {
        let data = call_api("/vpn/logicals").await?;

        fs::write(SERVER_INFO_FILE.as_path(), data)?;
        change_file_owner(SERVER_INFO_FILE.as_path())?;

        set_config_value("metadata", "last_api_pull", &time().to_string());
    }

    Ok(())
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Logicals {
    pub code: u32,
    pub logical_servers: Vec<LogicalServer>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct LogicalServer {
    pub name: String,
    pub entry_country: String,
    pub exit_country: String,
    pub domain: String,
    pub tier: Tier,
    pub features: Feature,
    pub region: Option<String>,
    pub city: Option<String>,
    #[serde(rename = "ID")]
    pub id: String,
    pub location: Location,
    pub status: u8,
    pub servers: Vec<Server>,
    pub load: u8,
    pub score: f64,
}

impl PartialOrd for LogicalServer {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.score.partial_cmp(&other.score)
    }
}

impl Ord for LogicalServer {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.partial_cmp(other).unwrap()
    }
}

impl PartialEq for LogicalServer {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}
impl Eq for LogicalServer {}

#[repr(u8)]
#[derive(Serialize_repr, Deserialize_repr, PartialEq, Eq, Debug)]
pub(crate) enum Feature {
    Normal = 0,
    SecureCore = 1,
    Tor = 2,
    P2P = 4,
}

impl Display for Feature {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Serialize_repr, Deserialize_repr, PartialEq, Eq, Debug, PartialOrd, Ord)]
#[repr(u8)]
pub(crate) enum Tier {
    Free = 0,
    Basic = 1,
    Plus = 2,
}

impl From<u8> for Tier {
    fn from(val: u8) -> Self {
        match val {
            0 => Self::Free,
            1 => Self::Basic,
            2 => Self::Plus,
            _ => panic!("invalid tier"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct Server {
    #[serde(rename = "EntryIP")]
    pub entry_ip: Ipv4Addr,
    #[serde(rename = "ExitIP")]
    pub exit_ip: Ipv4Addr,
    pub domain: String,
    #[serde(rename = "ID")]
    pub id: String,
    pub status: u8,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct Location {
    pub lat: f64,
    pub long: f64,
}

pub(crate) fn get_servers() -> Vec<LogicalServer> {
    // TODO: fail to parse or load => fetch servers
    let json = fs::File::open(SERVER_INFO_FILE.as_path()).expect("opening SERVER_INFO_FILE");
    println!("{:?}", json);
    let server_data: Logicals = serde_json::from_reader(json).expect("JSON to Server");

    let tier = u8::from_str_radix(&get_config_value("USER", "tier").unwrap(), 10).unwrap();
    let tier = Tier::from(tier);

    server_data
        .logical_servers
        .into_iter()
        .filter(|s| s.tier <= tier && s.status == 1)
        .collect()
}

pub(crate) fn get_server_value<'s>(
    servername: &str,
    servers: &'s [LogicalServer],
) -> Option<&'s LogicalServer> {
    servers.iter().find(|s| s.name == servername)
}

pub(crate) fn get_config_value(group: &str, key: &str) -> Option<String> {
    Ini::load_from_file(CONFIG_FILE.to_str().expect("config file to str"))
        .expect("couldnt load cfg file")
        .get_from(Some(group), key)
        .map(str::to_string)
}

pub(crate) fn set_config_value(group: &str, key: &str, value: &str) {
    Ini::load_from_file(CONFIG_FILE.to_str().expect("cfg to str"))
        .expect("couldnt load cfg file")
        .with_section(Some(group))
        .set(key, value);
}

#[allow(non_snake_case)]
#[derive(Debug, Serialize, Deserialize)]
struct VpnLocation {
    Code: i32,
    IP: Ipv4Addr,
    Lat: f64,
    Long: f64,
    Country: String,
    ISP: String,
}

pub(crate) async fn get_ip_info() -> Result<(Ipv4Addr, String)> {
    let ip_info = call_api("/vpn/location").await?;
    let info = String::from_utf8(ip_info.into_iter().collect())?;
    let loc_info: VpnLocation = serde_json::from_str(&info)?;
    Ok((loc_info.IP, loc_info.ISP))
}

pub(crate) fn get_country_name(code: &str) -> &str {
    COUNTRY_CODES.get(code).unwrap()
}

pub(crate) fn get_fastest_server(
    server_pool: &mut [utils::LogicalServer],
) -> &utils::LogicalServer {
    server_pool.sort();

    if server_pool.len() >= 50 {
        server_pool[..4].choose(&mut thread_rng()).unwrap()
    } else {
        &server_pool[0]
    }
}

pub(crate) fn get_default_nic() -> Result<String> {
    let ip_show_output = Command::new("ip").arg("route").arg("show").output()?.stdout;

    for ln in String::from_utf8(ip_show_output)?.split_terminator('\n') {
        if &ln[..7] == "default" {
            return Ok(ln
                .split_whitespace()
                .nth(4)
                .expect("unexpected ip route output")
                .to_string());
        }
    }

    anyhow::bail!("no default nic found");
}

pub(crate) fn is_connected() -> Result<bool> {
    Ok(Command::new("pgrep")
        .arg("--exact")
        .arg("openvpn")
        .status()?
        .success())
}

pub(crate) async fn wait_for_network(wait_time: u64) -> Result<()> {
    let start = time();
    while time() - start < wait_time && call_api("/test/ping").await.is_err() {
        std::thread::sleep(std::time::Duration::from_secs(2));
    }

    if time() - start >= wait_time {
        Err(anyhow!("connection timed out"))
    } else {
        std::thread::sleep(std::time::Duration::from_secs(2));
        println!("connection working!");
        Ok(())
    }
}

pub(crate) fn change_file_owner(path: &std::path::Path) -> Result<()> {
    let curr_owner = fs::metadata(path)?.st_uid();
    let u_id = users::get_effective_uid();

    if curr_owner != u_id {
        let g_id = users::get_effective_gid();
        unistd::chown(path, Uid::from_raw(u_id).into(), Gid::from_raw(g_id).into())?;
    }

    Ok(())
}

pub(crate) fn check_root() -> Result<()> {
    let user = env::var("LOGNAME").or_else(|_| env::var("NAME"))?;
    if user != "root" {
        println!("[!] The program was not executed as root.\n[!] Please run as root.");
        std::process::exit(1);
    }

    let deps = &["openvpn", "ip", "sysctl", "pgrep", "pkill"];
    for prog in deps {
        let output = Command::new("which")
            .arg(prog)
            .output()
            .expect("command not found");

        if !output.status.success() {
            println!("{0:?} not found.\nPlease install {0}", prog);
            std::process::exit(1);
        }
    }

    println!("root!");
    Ok(())
}

pub(crate) fn check_update() {
    todo!("check for update")
}

/// Default: true
pub(crate) fn check_init() {
    match get_config_value("USER", "initialized") {
        Some(x) if x == "0" => {
            let required_props = &[
                "username",
                "tier",
                "default_protocol",
                "dns_leak_protection",
                "custom_dns",
            ];

            // TODO: check initialisation

            for prop in required_props {
                if get_config_value("USER", prop).is_none() {
                    println!("[!] {} is missing from configuration.", prop);
                    println!("[!] Please run 'protonvpn configure' to set it.");
                    std::process::exit(1);
                }
            }
        }
        _ => {
            println!("[!] There has beeen no profile initialized yet.");
            println!("Please run 'protonvpn init'.");
            std::process::exit(1);
        }
    }
    println!("init!");
}

fn is_valid_ip(ipaddr: &str) -> bool {
    lazy_static! {
        static ref RE: Regex = Regex::new(
            "^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?).\
            (25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?).\
            (25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?).\
            (25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\
            (/(3[0-2]|[12][0-9]|[1-9]))?$",
        )
        .unwrap();
    }
    RE.is_match(ipaddr)
}

pub(crate) fn make_ovpn_template() {
    todo!("make ovpn template");
}

pub(crate) fn configure_cli() {
    todo!("config cli")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_regex() {
        assert!(is_valid_ip("192.168.0.1"))
    }

    #[test]
    fn test_check_init() {
        check_init(false);
        check_init(true);
    }

    #[test]
    fn test_default_nic() {
        let nic = get_default_nic().unwrap();
        assert!(["enp9s0", "wlp8s0"].contains(&&nic[..]))
    }

    #[test]
    #[ignore]
    fn test_connected() {
        assert!(is_connected().unwrap());
    }
}
