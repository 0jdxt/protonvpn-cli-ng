use crate::constants::{CONFIG_FILE, SERVER_INFO_FILE};

use anyhow::{anyhow, Result};
use hyper::body::{Bytes, HttpBody};
use hyper::{Body, Client, Request, Uri};
use ini::Ini;
use lazy_static::lazy_static;
use nix::unistd::{self, Gid, Uid};
use rand::seq::SliceRandom;
use rand::thread_rng;
use regex::Regex;
use serde_derive::{Deserialize, Serialize};
use serde_json::Value;

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::os::linux::fs::MetadataExt;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) async fn call_api(endpoint: &str) -> Result<Bytes> {
    let url = Uri::builder()
        .scheme("https")
        .authority("api.protonmail.ch")
        .path_and_query(endpoint)
        .build()?;

    let req = Request::get(url)
        .header("x-pm-appversion", "Other")
        .header("x-pm-apiversion", "3")
        .header("Accept", "application/vnd.protonmail.v1+json")
        .body(Body::empty())?;

    Ok(Client::new()
        .request(req)
        .await?
        .body_mut()
        .data()
        .await
        .unwrap()?)
}

pub(crate) fn time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_secs()
}

pub(crate) async fn pull_server_data(force: bool) -> Result<()> {
    let mut cfg = Ini::load_from_file(CONFIG_FILE.as_path())?;
    let last_pull = cfg.get_from(Some("metadata"), "last_api_pull").unwrap();

    if force || time() - u64::from_str_radix(last_pull, 10)? > 900 {
        let data = call_api("/vpn/logicals").await?;

        fs::write(SERVER_INFO_FILE.as_path(), data)?;
        change_file_owner(&SERVER_INFO_FILE)?;

        cfg.set_to(Some("metadata"), "last_api_pull".into(), time().to_string());
        cfg.write_to_file(CONFIG_FILE.as_path())?;
    }

    Ok(())
}

pub(crate) fn get_servers() -> Vec<Value> {
    let server_data: Value =
        serde_json::from_str(&fs::read_to_string(SERVER_INFO_FILE.as_path()).unwrap()).unwrap();
    let servers = server_data.get("LogicalServers");
    let tier = u64::from_str_radix(&get_config_value("USER", "tier").unwrap(), 10).unwrap();
    servers
        .into_iter()
        .filter(|s| match s.get("Tier") {
            Some(Value::Number(x)) => x.as_u64().unwrap() <= tier,
            _ => false
        } && match s.get("Status") {
            Some(Value::Number(x)) => x.as_u64().unwrap() == 1,
            _ => false
        }).cloned().collect()
}

pub(crate) fn get_server_value<'v>(
    servername: &str,
    key: &str,
    servers: &'v [Value],
) -> Option<&'v Value> {
    servers
        .iter()
        .filter_map(|s| {
            if match s.get("Name") {
                Some(Value::String(name)) => name == servername,
                _ => false,
            } {
                s.get(key)
            } else {
                None
            }
        })
        .nth(0)
}

fn get_config_value(group: &str, key: &str) -> Option<String> {
    Ini::load_from_file(CONFIG_FILE.to_str().expect("config file to str"))
        .expect("couldnt load cfg file")
        .get_from(Some(group), key)
        .map(str::to_string)
}

fn set_config_value(group: &str, key: &str, value: &str) {
    Ini::load_from_file(CONFIG_FILE.to_str().expect("cfg to str"))
        .expect("couldnt load cfg file")
        .with_section(Some(group))
        .set(key, value);
}

#[derive(Serialize, Deserialize)]
struct VpnLocation {
    Code: i32,
    IP: String,
    Lat: f64,
    Long: f64,
    Country: String,
    ISP: String,
}

async fn get_ip_info() -> Result<(String, String)> {
    let ip_info = call_api("/vpn/location").await?;
    let info = String::from_utf8(ip_info.into_iter().collect())?;
    let loc_info: VpnLocation = serde_json::from_str(&info)?;
    Ok((loc_info.IP, loc_info.ISP))
}

fn get_country_name(code: &str) -> &str {
    unimplemented!()
}

// TODO: turn this into Serde JSON
#[derive(Clone, Copy)]
struct Server {
    Score: u64,
}

pub(crate) fn get_fastest_server(server_pool: &mut [serde_json::Value]) -> &serde_json::Value {
    server_pool[..].sort_by_key(|s| s.get("Score").unwrap().as_u64().unwrap());
    let pool_size = if server_pool.len() >= 50 { 4 } else { 1 };
    server_pool[..pool_size].choose(&mut thread_rng()).unwrap()
}

fn get_default_nic() -> Result<String> {
    let ip_show = Command::new("ip").arg("route").arg("show").output()?.stdout;

    for ln in String::from_utf8(ip_show)?.split_terminator('\n') {
        if &ln[..7] == "default" {
            return Ok(ln.split_whitespace().nth(4).unwrap().to_string());
        }
    }

    Err(anyhow!("no default nic found"))
}

fn is_connected() -> Result<bool> {
    Ok(Command::new("pgrep")
        .arg("--exact")
        .arg("openvpn")
        .status()?
        .success())
}

pub async fn wait_for_network(wait_time: u64) -> Result<()> {
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

fn change_file_owner(path: &std::path::PathBuf) -> Result<()> {
    let curr_owner = fs::metadata(path.as_path())?.st_uid();
    let uid = users::get_effective_uid();

    if curr_owner != uid {
        let gid = users::get_effective_gid();
        unistd::chown(path, Uid::from_raw(uid).into(), Gid::from_raw(gid).into())?;
    }

    Ok(())
}

pub(crate) fn check_root() -> Result<()> {
    let user = env::var("LOGNAME").or(env::var("NAME"))?;
    if user != "root" {
        println!("[!] The program was not executed as root.");
        println!("[!] Please run as root.");
        std::process::exit(1);
    }

    let deps = &["openvpn", "ip", "sysctl", "pgrep", "pkill"];
    for prog in deps {
        let status = Command::new("command")
            .arg(prog)
            .status()
            .expect("command not found");

        if !status.success() {
            println!("{0:?} not found.\nPlease install {0}", prog);
            std::process::exit(1);
        }
    }

    Ok(())
}

pub(crate) fn check_update() {
    unimplemented!("check for update")
}

pub(crate) fn check_init(check_props: bool) {
    match get_config_value("USER", "initialized") {
        Some(x) if x != "0" => {
            if check_props {
                let required_props = &[
                    "username",
                    "tier",
                    "default_protocol",
                    "dns_leak_protection",
                    "custom_dns",
                ];

                for prop in required_props {
                    if get_config_value("USER", prop).is_none() {
                        println!("[!] {} is missing from configuration.", prop);
                        println!("[!] Please run 'protonvpn configure' to set it.");
                        std::process::exit(1);
                    }
                }
            }
        }
        _ => {
            println!("[!] There has beeen no profile initialized yet.");
            println!("Please run 'protonvpn init'.");
            std::process::exit(1);
        }
    }
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
        assert_eq!("eth0", get_default_nic().unwrap())
    }
}
