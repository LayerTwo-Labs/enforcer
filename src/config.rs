use std::{collections::HashMap, net::SocketAddr, path::PathBuf};

use clap::Parser;
use serde::{Deserialize, Serialize};

#[derive(Parser, Serialize, Deserialize, Default, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Config {
    #[arg(long)]
    pub main_rpchost: Option<String>,
    #[arg(long)]
    pub main_rpcport: Option<u16>,
    /// Datadir of mainchain Bitcoin Core node
    #[arg(short, long)]
    pub main_datadir: Option<PathBuf>,
    /// Datadir of enforcer
    #[arg(short, long)]
    pub datadir: Option<PathBuf>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SoftForks {
    soft_forks: HashMap<String, SocketAddr>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SoftFork {
    name: String,
    rpc_addr: SocketAddr,
}
