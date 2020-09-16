
use json_rpc::client::JsonRpcAsyncClinet;
use serde_json::{json, Value};
use reqwest::{Client, ClientBuilder, Error};
use lcs::from_bytes;
use libra_types::views::BytesView;


async fn test_rpc_get_account() -> Result<(), Error>{
    let result = JsonRpcAsyncClinet::new("http://client.testnet.libra.org/v1")
        .get_account("1668f6be25668c1a17cd8caf6b8d2f25").await?;
    println!("{:#?}", result);
    Ok(())
}

async fn test_rpc_get_account_state_with_proof() -> Result<(), Error>{
    let result = JsonRpcAsyncClinet::new("http://client.testnet.libra.org/v1")
        .get_account_state_with_proof("1668f6be25668c1a17cd8caf6b8d2f25", &2254856,&2254879).await?;
    println!("{:#?}", result);
    Ok(())
}

async fn test_rpc_get_state_proof() -> Result<(), Error>{
    let result = JsonRpcAsyncClinet::new("http://client.testnet.libra.org/v1")
        .get_state_proof( &2054879).await?;
    println!("{:#?}", result);
    Ok(())
}

async fn test_rpc_get_currencies() -> Result<(), Error>{
    let result = JsonRpcAsyncClinet::new("http://client.testnet.libra.org/v1")
        .get_currencies().await?;
    println!("{:#?}", result);
    Ok(())
}

async fn test_rpc_get_account_transaction() -> Result<(), Error> {
    let result = JsonRpcAsyncClinet::new("http://client.testnet.libra.org/v1")
        .get_account_transaction("1668f6be25668c1a17cd8caf6b8d2f25", &0, false).await?;
    println!("{:#?}", result);
    Ok(())
}

// async fn test_lcs() -> Result<(), Error> {
//     let result = JsonRpcAsyncClinet::new("http://client.testnet.libra.org/v1")
//         .get_currencies().await.expect("rpc errpr");
//     let start_version: u64 = result["libra_ledger_version"].as_u64().expect("version error");
//     let result = JsonRpcAsyncClinet::new("http://client.testnet.libra.org/v1")
//         .get_state_proof(&2053726).await.expect("rpc error");
//     let epoch_change_proof:String = (result.get("result")
//         .expect(""))["ledger_info_with_signatures"]
//         .as_str()
//         .expect("")
//         .to_string();
//     let epoch_change_proof_byte:BytesView = BytesView::from(hex::decode(epoch_change_proof).expect(""));
//     println!("{:#?}", epoch_change_proof_byte);
//
//     // let epoch_change_proof_json:BytesView = lcs::from_bytes(&epoch_change_proof_byte.into_bytes().expect("")).expect("");
//     // println!("{:#?}", epoch_change_proof_json);
//     //
//
//     // let ledger_info_with_signatures:String = (result.get("result")
//     //     .unwrap())["ledger_info_with_signatures"]
//     //     .as_str()
//     //     .unwrap()
//     //     .to_string();
//     Ok(())
// }




#[tokio::main]
async fn main() -> Result<(), Error>{
    test_rpc_get_state_proof().await?;
    Ok(())

}