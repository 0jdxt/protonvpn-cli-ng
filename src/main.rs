#![warn(clippy::all, clippy::pedantic)]

mod cli;
mod connection;
mod constants;
mod utils;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("{}", *constants::USER);
    println!("{:?}", *constants::HOME_DIR);
    println!("{:?}", std::env::var("HOME"));
    cli::cli().await
}
