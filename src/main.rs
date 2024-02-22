use std::io::Write;
use std::path::Path;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{fs::File, io::Cursor};

use bitcoin::absolute::{Height, LockTime};
use bitcoin::block::Version;
use bitcoin::consensus::Encodable;
use bitcoin::constants::genesis_block;
use bitcoin::hashes::Hash;
use bitcoin::opcodes::OP_0;
use bitcoin::{consensus::Decodable, Block};
use bitcoin::{
    merkle_tree, Amount, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Target,
    Transaction, TxIn, TxMerkleNode, TxOut, Txid, Witness,
};
use miette::{miette, IntoDiagnostic, Result};
use serde::{Deserialize, Serialize};
use ureq_jsonrpc::{json, Client};

use clap::Parser;

mod client;
mod config;

/*
#[tokio::main]
async fn main() -> Result<()> {
    client::run_client().await?;
    Ok(())
}
*/

#[tokio::main]
async fn main() -> Result<()> {
    let cli_config = config::Config::parse();
    dbg!(&cli_config);
    let data_dir = dirs::data_dir()
        .ok_or(miette!("failed to get default data dir"))?
        .join("soft_fork_enforcer");
    let config: config::Config =
        confy::load_path(&data_dir.join("config.toml")).into_diagnostic()?;

    dbg!(config);
    dbg!(&data_dir);

    let main_datadir = Path::new("../../data/bitcoin/");
    let main_client = create_client(main_datadir)?;

    let mut current_block_height = 0;
    if let Ok(data_str) = std::fs::read_to_string(data_dir.join("data.toml")) {
        let data: Data = toml::from_str(&data_str).into_diagnostic()?;
        println!("read: {:?}", &data);
        current_block_height = data.block_height;
    }

    loop {
        submit_block(&main_client).await?;

        let new_block_height: u32 = main_client
            .send_request("getblockcount", &[])?
            .ok_or(miette!("failed to get block count"))?;

        if current_block_height != new_block_height {
            for block_height in (current_block_height + 1)..=new_block_height {
                let block_hash: String = main_client
                    .send_request("getblockhash", &[json!(block_height)])?
                    .ok_or(miette!("failed to get block hash"))?;

                let block_hex: String = main_client
                    .send_request("getblock", &[json!(block_hash), json!(0)])?
                    .ok_or(miette!("failed to get block"))?;
                let block_bytes: Vec<u8> = hex::decode(block_hex).into_diagnostic()?;
                client::run_client(&block_bytes, block_height).await?;
                let mut cursor = Cursor::new(block_bytes);
                let block = Block::consensus_decode(&mut cursor).into_diagnostic()?;

                dbg!(&block);

                if is_valid(&block) {
                    connect_block(&block)?;
                }

                println!("Processing Block: {block_height} {block_hash}",);
            }
            println!("Block Height: {new_block_height}");
            let data = Data {
                block_height: new_block_height,
            };
            println!("wrote: {:?}", &data);
            let data_str = toml::to_string(&data).into_diagnostic()?;
            let mut file = File::create(data_dir.join("data.toml")).into_diagnostic()?;
            file.write_all(&data_str.into_bytes()).into_diagnostic()?;
            current_block_height = new_block_height;
        }

        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    // read_blocks()?;
}

fn is_valid(block: &Block) -> bool {
    false
}

fn connect_block(block: &Block) -> Result<()> {
    Ok(())
}

fn disconnect_block(block: &Block) -> Result<()> {
    // store 100 last blocks.
    Ok(())
}

#[derive(Serialize, Deserialize, Debug)]
struct Data {
    block_height: u32,
}

fn create_client(main_datadir: &Path) -> Result<Client> {
    let auth = std::fs::read_to_string(main_datadir.join("regtest/.cookie")).into_diagnostic()?;
    let mut auth = auth.split(":");
    let user = auth
        .next()
        .ok_or(miette!("failed to get rpcuser"))?
        .to_string();
    let password = auth
        .next()
        .ok_or(miette!("failed to get rpcpassword"))?
        .to_string();
    Ok(Client {
        host: "localhost".into(),
        port: 18443,
        user,
        password,
        id: "mainchain".into(),
    })
}

use client::validator::validator_client::ValidatorClient;

use crate::client::validator::{AckSidechain, GetCoinbasePsbtRequest, ProposeSidechain};

async fn submit_block(main_client: &Client) -> Result<()> {
    let mut client = ValidatorClient::connect("http://[::1]:50051")
        .await
        .into_diagnostic()?;

    let request = tonic::Request::new(GetCoinbasePsbtRequest {
        propose_sidechains: vec![],
        ack_sidechains: vec![
            AckSidechain {
                sidechain_number: 0,
                data_hash: sha256d(b"thunder").to_vec(),
            },
            AckSidechain {
                sidechain_number: 1,
                data_hash: sha256d(b"bitnames").to_vec(),
            },
        ],
        propose_bundles: vec![],
        ack_bundles: None,
    });
    let response = client.get_coinbase_psbt(request).await.into_diagnostic()?;
    let mut cursor = Cursor::new(response.into_inner().psbt.clone());
    let transaction = Transaction::consensus_decode(&mut cursor).into_diagnostic()?;

    let block_height: u32 = main_client
        .send_request("getblockcount", &[])?
        .ok_or(miette!("failed to get block count"))?;
    let block_hash: String = main_client
        .send_request("getblockhash", &[json!(block_height)])?
        .ok_or(miette!("failed to get block hash"))?;
    let prev_blockhash = BlockHash::from_str(&block_hash).into_diagnostic()?;

    let start = SystemTime::now();
    let time = start
        .duration_since(UNIX_EPOCH)
        .into_diagnostic()?
        .as_secs() as u32;

    let script_sig = bitcoin::blockdata::script::Builder::new()
        .push_int((block_height + 1) as i64)
        .push_opcode(OP_0)
        .into_script();

    let txdata = vec![Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::Blocks(Height::ZERO),
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::all_zeros(),
                vout: 0xFFFF_FFFF,
            },
            sequence: Sequence::MAX,
            witness: Witness::new(),
            script_sig,
        }],
        output: transaction.output,
    }];

    let mut tx_hashes: Vec<_> = txdata.iter().map(Transaction::txid).collect();
    let merkle_root: TxMerkleNode = merkle_tree::calculate_root_inline(&mut tx_hashes)
        .unwrap()
        .to_raw_hash()
        .into();

    let genesis_block = genesis_block(bitcoin::Network::Regtest);
    let bits = genesis_block.header.bits;
    let mut header = bitcoin::block::Header {
        version: Version::NO_SOFT_FORK_SIGNALLING,
        prev_blockhash,
        merkle_root,
        time,
        bits,
        nonce: 0,
    };
    loop {
        header.nonce += 1;
        if header.validate_pow(header.target()).is_ok() {
            break;
        }
    }
    let block = Block { header, txdata };
    dbg!(&block);
    let mut block_bytes = vec![];
    block.consensus_encode(&mut block_bytes).into_diagnostic()?;
    let block_hex = hex::encode(block_bytes);
    println!("block hex: {block_hex}",);

    let _: Option<()> = main_client.send_request("submitblock", &[json!(block_hex)])?;
    Ok(())
}

use sha2::{Digest, Sha256};

pub fn sha256d(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let data_hash: [u8; 32] = hasher.finalize_reset().into();
    hasher.update(data_hash);
    let data_hash: [u8; 32] = hasher.finalize().into();
    data_hash
}
