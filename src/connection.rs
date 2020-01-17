use crate::utils;
use anyhow::Result;
use rand::{self, seq::SliceRandom};

fn dialog() {
    unimplemented!()
}

async fn random_c(protocol: &str) -> Result<()> {
    let servers = utils::get_servers();
    let servername = servers
        .choose(&mut rand::thread_rng())
        .unwrap()
        .get("Name")
        .unwrap()
        .as_str()
        .unwrap();
    openvpn_connect(servername, protocol).await
}

async fn fastest(protocol: &str) -> Result<()> {
    //disconnect(true);
    utils::pull_server_data(true).await?;

    let servers = utils::get_servers();
    let mut pool = servers
        .into_iter()
        .filter_map(|s| match s.get("Features") {
            Some(serde_json::Value::Number(n)) if [1, 2].contains(&n.as_u64().unwrap()) => Some(s),
            _ => None,
        })
        .collect::<Vec<_>>();
    let fastest_server = utils::get_fastest_server(&mut pool).get("Name").unwrap();
    openvpn_connect(fastest_server.as_str().unwrap(), protocol).await
}

async fn openvpn_connect(servername: &str, protocol: &str) -> Result<()> {
    // TODO: copy template to ovpn file
    Ok(())
}
