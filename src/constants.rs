use dirs::home_dir;
use lazy_static::lazy_static;
use std::path::PathBuf;

macro_rules! config_dir {
    ($file:expr) => {{
        let mut p = CONFIG_DIR.clone();
        p.push($file);
        p
    }};
}

lazy_static! {
    static ref USER: String = std::env::var("SUDO_USER")
        .or(users::get_effective_username()
            .expect("no current user")
            .into_string())
        .expect("user into string");
    static ref HOME_DIR: PathBuf = home_dir().expect("Could not find user home directory");
    pub static ref CONFIG_DIR: PathBuf = {
        let mut p = HOME_DIR.clone();
        p.push(".pvpn-cli");
        p
    };
    pub static ref CONFIG_FILE: PathBuf = config_dir!("pvpn-cli.cfg");
    pub static ref TEMPLATE_FILE: PathBuf = config_dir!("template.ovpn");
    pub static ref SERVER_INFO_FILE: PathBuf = config_dir!("serverinfo.json");
    pub static ref SPLIT_TUNNEL_FILE: PathBuf = config_dir!("split_tunnel.txt");
    pub static ref OVPN_FILE: PathBuf = config_dir!("connect.ovpn");
    pub static ref PASSFILE: PathBuf = config_dir!("pvpnpass");
}
