use std::io::Cursor;

use bitcoin::consensus::Decodable;
use bitcoin::Transaction;
use miette::{IntoDiagnostic, Result};
use validator::validator_client::ValidatorClient;
use validator::{ConnectBlockRequest, ConnectBlockResponse};
use validator::{DisconnectBlockRequest, DisconnectBlockResponse};
use validator::{IsValidRequest, IsValidResponse};

use crate::client::validator::{AckSidechain, GetCoinbasePsbtRequest, ProposeSidechain};

pub mod validator {
    tonic::include_proto!("validator"); // The string specified here must match the proto package name
}

pub async fn run_client(block: &[u8], height: u32) -> Result<()> {
    let mut client = ValidatorClient::connect("http://[::1]:50051")
        .await
        .into_diagnostic()?;
    let request = tonic::Request::new(IsValidRequest {
        block: block.to_vec(),
    });
    let response = client.is_valid(request).await.into_diagnostic()?;
    //println!("RESPONSE={:?}", response);
    let request = tonic::Request::new(ConnectBlockRequest {
        block: block.to_vec(),
        height,
    });
    let response = client.connect_block(request).await.into_diagnostic()?;
    let request = tonic::Request::new(DisconnectBlockRequest {
        block: block.to_vec(),
    });
    let response = client.disconnect_block(request).await.into_diagnostic()?;

    let request = tonic::Request::new(GetCoinbasePsbtRequest {
        propose_sidechains: vec![
            ProposeSidechain {
                sidechain_number: 0,
                data: b"thunder".to_vec(),
            },
            ProposeSidechain {
                sidechain_number: 1,
                data: b"bitnames".to_vec(),
            },
        ],
        ack_sidechains: vec![],
        propose_bundles: vec![],
        ack_bundles: None,
    });
    let response = client.get_coinbase_psbt(request).await.into_diagnostic()?;
    let mut cursor = Cursor::new(response.into_inner().psbt.clone());
    let transaction = Transaction::consensus_decode(&mut cursor);
    println!("RESPONSE={:?}", transaction);
    Ok(())
}
