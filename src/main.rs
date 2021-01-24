use structopt::StructOpt;

use diem_client::{
    AccountData,
    AccountStatus,
};
use rand::{rngs::OsRng, Rng, SeedableRng};
use anyhow::{ensure, Result};
//use diem_logger::prelude::*;
use reqwest::Url;
use diem_crypto::{hash::{CryptoHash}, ed25519::{Ed25519PrivateKey, Ed25519PublicKey, }, Uniform, test_utils::KeyPair, ValidCryptoMaterialStringExt};
use swiss_knife::generator::{
    GenerateRawTxnRequest, GenerateRawTxnResponse,
    GenerateSignedTxnRequest, GenerateSignedTxnResponse,
    SignTransactionUsingEd25519Request, SignTransactionUsingEd25519Response,
    generate_raw_txn, generate_signed_txn, sign_transaction_using_ed25519,
};

use diem_types::{
    account_address::{
        AccountAddress,
    },
    chain_id::ChainId,
    ledger_info::LedgerInfoWithSignatures,
    transaction::{
        TransactionInfo,
        authenticator::AuthenticationKey,
    },
    epoch_change::EpochChangeProof,
    proof::{
        AccountStateProof,
        TransactionInfoWithProof,
        TransactionAccumulatorProof,
        SparseMerkleProof,
    },
    trusted_state::{TrustedState, TrustedStateChange},
};
use diem_json_rpc_client::{
    get_response_from_batch,
    views::{
        AccountStateWithProofView, AccountView, BytesView,
        EventView, StateProofView, TransactionView
    },
    JsonRpcBatch, JsonRpcClient, ResponseAsView,
};
use std::{convert::TryFrom};
use diem_json_rpc_types::views::AmountView;
use diem_types::account_state_blob::AccountStateBlob;
use std::ops::Add;

mod pruntime_client;
mod types;
mod error;

type PrClient = pruntime_client::PRuntimeClient;

const DIEM_CONTRACT_ID: u32 = 5;

use crate::error::Error;
use crate::types::QueryReqData;

use serde::{Serialize, Deserialize};

#[derive(Debug, StructOpt)]
#[structopt(name = "pDiem")]
struct Args {
    #[structopt(
    default_value = "http://127.0.0.1:8080", long,
    help = "Diem rpc endpoint")]
    diem_rpc_endpoint: String, //official rpc endpoint: https://testnet.diem.com/v1

    #[structopt(
    default_value = "http://127.0.0.1:8000", long,
    help = "pRuntime http endpoint")]
    pruntime_endpoint: String,
}

pub struct DiemDemo {
    chain_id: ChainId,
    rpc_client: JsonRpcClient,
    epoch_change_proof: Option<EpochChangeProof>,
    trusted_state: Option<TrustedState>,
    latest_epoch_change_li: Option<LedgerInfoWithSignatures>,
    latest_li: Option<LedgerInfoWithSignatures>,
    sent_events_key: Option<BytesView>,
    received_events_key:Option<BytesView>,
    sent_events: Option<Vec<EventView>>,
    received_events: Option<Vec<EventView>>,
    transactions: Option<Vec<TransactionView>>,
    account: Option<AccountData>,
    balances: Option<Vec<AmountView>>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Amount {
    pub amount: u64,
    pub currency: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    pub address: AccountAddress,
    pub authentication_key: Option<Vec<u8>>,
    pub sequence_number: u64,
    pub sent_events_key: String,
    pub received_events_key: String,
    pub balances: Vec<Amount>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionWithProof {
    transaction_bytes: Vec<u8>,

    epoch_change_proof: EpochChangeProof,
    ledger_info_with_signatures: LedgerInfoWithSignatures,

    ledger_info_to_transaction_info_proof: TransactionAccumulatorProof,
    transaction_info: TransactionInfo,
    transaction_info_to_account_proof: SparseMerkleProof,
    account_state_blob: AccountStateBlob,

    version: u64,
}

impl DiemDemo {
    pub fn new(url: &str) -> Result<Self> {
        let rpc_client = JsonRpcClient::new(Url::parse(url).unwrap()).unwrap();
        Ok(DiemDemo {
            chain_id: ChainId::new(2),
            rpc_client,
            sent_events_key: None,
            received_events_key: None,
            epoch_change_proof: None,
            trusted_state: None,
            latest_epoch_change_li: None,
            latest_li: None,
            sent_events: None,
            received_events: None,
            transactions:None,
            account: None,
            balances: None,
        })
    }

    fn verify_state_proof(
        &mut self,
        li: LedgerInfoWithSignatures,
        epoch_change_proof: EpochChangeProof
    ) -> Result<()> {
        let client_version = self.trusted_state.as_mut().unwrap().latest_version();
        // check ledger info version
        ensure!(
            li.ledger_info().version() >= client_version,
            "Got stale ledger_info with version {}, known version: {}",
            li.ledger_info().version(),
            client_version,
        );

        // trusted_state_change
        match self
            .trusted_state
            .as_mut()
            .unwrap()
            .verify_and_ratchet(&li, &epoch_change_proof)?
        {
            TrustedStateChange::Epoch {
                new_state,
                latest_epoch_change_li,
            } => {
                println!(
                    "Verified epoch changed to {}",
                    latest_epoch_change_li
                        .ledger_info()
                        .next_epoch_state()
                        .expect("no validator set in epoch change ledger info"),
                );
                // Update client state
                self.trusted_state = Option::from(new_state);
                self.latest_epoch_change_li = Some(latest_epoch_change_li.clone());
            }
            TrustedStateChange::Version { new_state } => {
                if self.trusted_state.as_mut().unwrap().latest_version() < new_state.latest_version() {
                    println!("Verified version change to: {}", new_state.latest_version());
                }
                self.trusted_state = Option::from(new_state);
            }
            TrustedStateChange::NoChange => (),
        }
        Ok(())
    }

    pub fn _generate_account(
        &mut self
    ) -> Result<()> {
        let mut seed_rng = OsRng;
        let mut rng = rand::rngs::StdRng::from_seed(seed_rng.gen());
        let keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey> =
            Ed25519PrivateKey::generate(&mut rng).into();
        let libra_auth_key = AuthenticationKey::ed25519(&keypair.public_key).to_vec();
        let libra_account_address = AuthenticationKey::ed25519(&keypair.public_key).derived_address();
        let account_data = AccountData {
            address: libra_account_address,
            authentication_key: Option::from(libra_auth_key),
            key_pair: Option::from(keypair),
            sequence_number: 0,
            status: AccountStatus::Local
        };
        self.account = Option::from(account_data);
        println!("{:#?}", self.account);
        Ok(())
    }

    pub fn _generate_transaction(
        &mut self
    ) -> Result<()> {
        let tx_json = serde_json::json!({
            "txn_params": {
            "sender_address": "0xd4f0c053205ba934bb2ac0c4e8479e77",
            "sequence_number": 0,
            "max_gas_amount": 1000000,
            "gas_unit_price": 0,
            "gas_currency_code": "XUS",
            "chain_id": "TESTING",
            "expiration_timestamp_secs": 1609585373
          },
          "script_params": {
            "peer_to_peer_transfer": {
              "coin_tag": "XUS",
              "recipient_address": "0x57c76da2e144c0357336ace2f3f8ac9b",
              "amount": 10,
              "metadata_hex_encoded": "",
              "metadata_signature_hex_encoded": ""
            }
          }
        });
        let mut g_res: GenerateRawTxnRequest = serde_json::from_value(tx_json).unwrap();
        g_res.txn_params.sender_address = String::from("0x").add(self.account.as_ref().unwrap().address.to_string().as_str());
        let g_resp:GenerateRawTxnResponse = generate_raw_txn(g_res);
        let s_res: SignTransactionUsingEd25519Request = SignTransactionUsingEd25519Request{
            raw_txn: g_resp.raw_txn.clone(),
            private_key: self.account.as_ref().unwrap().key_pair.as_ref().unwrap().private_key.to_encoded_string().unwrap().clone(),
        };
        let s_resp:SignTransactionUsingEd25519Response = sign_transaction_using_ed25519(s_res);
        let gs_res:GenerateSignedTxnRequest = GenerateSignedTxnRequest{
            raw_txn: g_resp.raw_txn.clone(),
            public_key: self.account.as_ref().unwrap().key_pair.as_ref().unwrap().public_key.to_encoded_string().unwrap().clone(),
            signature: s_resp.signature.clone(),
        };
        let gs_resp:GenerateSignedTxnResponse = generate_signed_txn(gs_res);

        println!("{:#?}", gs_resp.signed_txn);
        Ok(())
    }

    async fn _verify_transactions(
        &mut self,
        pr: &PrClient,
        account_address: String,
    ) -> Result<(), Error> {
        if self.transactions.is_none() || self.transactions.as_ref().unwrap().len() == 0 {
            println!("Account {:} has no transactions", account_address);
            return Ok(());
        }

        let transactions = self.transactions.as_ref().unwrap().clone();
        for transaction in transactions {
            let mut batch = JsonRpcBatch::new();
            let account = self.account.as_ref().unwrap().address.clone();
            batch.add_get_account_state_with_proof_request(account, Some(transaction.version), Some(self.trusted_state.as_ref().unwrap().latest_version()));
            let responses = self.rpc_client.execute(batch).unwrap();
            match get_response_from_batch(0, &responses).unwrap().as_ref() {
                Ok(resp) => {
                    let account_state_proof =
                        AccountStateWithProofView::from_response(resp.clone()).unwrap();

                    let ledger_info_to_transaction_info_proof: TransactionAccumulatorProof =
                        bcs::from_bytes(&account_state_proof.proof.ledger_info_to_transaction_info_proof.into_bytes().unwrap()).unwrap();
                    let transaction_info: TransactionInfo =
                        bcs::from_bytes(&account_state_proof.proof.transaction_info.into_bytes().unwrap()).unwrap();
                    let transaction_info_to_account_proof: SparseMerkleProof =
                        bcs::from_bytes(&account_state_proof.proof.transaction_info_to_account_proof.into_bytes().unwrap()).unwrap();
                    let account_state_blob: AccountStateBlob =
                        bcs::from_bytes(&account_state_proof.blob.unwrap().into_bytes().unwrap()).unwrap();
                    println!("hash: {:#?}", transaction_info.transaction_hash);

                    let transaction_info_with_proof = TransactionInfoWithProof::new(
                        ledger_info_to_transaction_info_proof.clone(),
                        transaction_info.clone()
                    );

                    let account_transaction_state_proof = AccountStateProof::new(
                        transaction_info_with_proof.clone(),
                        transaction_info_to_account_proof.clone(),
                    );
                    let _ = account_transaction_state_proof.verify(
                        self.latest_li.as_ref().unwrap().ledger_info(),
                        transaction.version,
                        self.account.as_ref().unwrap().address.hash(),
                        Some(&account_state_blob),
                    );
                    println!("Transaction was verified");

                    //now send proofs to pruntime
                    let transaction_with_proof = TransactionWithProof {
                        transaction_bytes: transaction.bytes.into_bytes().unwrap(),
                        epoch_change_proof: self.epoch_change_proof.clone().unwrap(),
                        ledger_info_with_signatures: self.latest_li.clone().unwrap(),
                        ledger_info_to_transaction_info_proof,
                        transaction_info,
                        transaction_info_to_account_proof,
                        account_state_blob,
                        version: transaction.version,
                    };

                    let transaction_with_proof_b64 = base64::encode(&bcs::to_bytes(&transaction_with_proof).unwrap());
                    println!("transaction_with_proof_b64:{:?}", transaction_with_proof_b64);

                    let resp = pr.query(DIEM_CONTRACT_ID, QueryReqData::VerifyTransaction
                        { account_address: account_address.clone(), transaction_with_proof_b64 }).await?;
                    println!("response: {:?}", resp);
                },
                Err(_) => {
                    println!("Failed to get account's state with proof");
                }
            }
        }
        Ok(())
    }

    pub fn init_state(
        &mut self
    ) -> Result<()> {
        let mut batch = JsonRpcBatch::new();
        batch.add_get_state_proof_request(0);

        let responses = self.rpc_client.execute(batch).unwrap();

        let resp = get_response_from_batch(0, &responses).unwrap().as_ref().unwrap();

        let state_proof = StateProofView::from_response(resp.clone()).unwrap();
        //println!("state_proof:\n{:?}", state_proof);

        let epoch_change_proof: EpochChangeProof =
            bcs::from_bytes(&state_proof.epoch_change_proof.into_bytes().unwrap()).unwrap();
        let ledger_info_with_signatures: LedgerInfoWithSignatures =
            bcs::from_bytes(&state_proof.ledger_info_with_signatures.into_bytes().unwrap()).unwrap();

        //let ledger_consistency_proof: AccumulatorConsistencyProof =
        //    bcs::from_bytes(&state_proof.ledger_consistency_proof.into_bytes().unwrap()).unwrap();
        // Init zero version state
        let zero_ledger_info_with_sigs = epoch_change_proof.ledger_info_with_sigs[0].clone();

        self.latest_epoch_change_li = Option::from(zero_ledger_info_with_sigs.clone());
        self.trusted_state = Option::from(TrustedState::try_from(zero_ledger_info_with_sigs.ledger_info()).unwrap());
        self.latest_li = Option::from(ledger_info_with_signatures.clone());
        self.epoch_change_proof = Option::from(epoch_change_proof.clone());

        // Update Latest version state
        let _ = self.verify_state_proof(ledger_info_with_signatures, epoch_change_proof);
        println!("trusted_state: {:#?}", self.trusted_state);
        println!("ledger_info_with_signatures: {:#?}", self.latest_li);
        Ok(())
    }


    async fn init_account(
        &mut self,
        pr: &PrClient,
        account_address: String,
    ) -> Result<(), Error> {
        // Init account information
        let mut batch = JsonRpcBatch::new();
        let address = AccountAddress::from_hex_literal(&account_address).unwrap();
        batch.add_get_account_request(address);
        let responses = self.rpc_client.execute(batch).unwrap();
        let resp = get_response_from_batch(0, &responses).unwrap().as_ref().unwrap();
        match AccountView::optional_from_response(resp.clone()).unwrap() {
            Some(account_view) => {
                self.account = Option::from(AccountData {
                    address,
                    authentication_key: account_view.authentication_key.into_bytes().ok(),
                    key_pair: None,
                    sequence_number: account_view.sequence_number,
                    status: AccountStatus::Persisted,
                });
                self.sent_events_key = Option::from(account_view.sent_events_key.clone());
                self.received_events_key = Option::from(account_view.received_events_key.clone());
                self.balances = Option::from(account_view.balances.clone());

                let balances: Vec<Amount> = self.balances.as_ref().unwrap()
                    .iter()
                    .map(|b| Amount{ amount: b.amount, currency: b.currency.clone() }).collect();

                let account_info = AccountInfo {
                    address: self.account.as_ref().unwrap().address,
                    authentication_key: self.account.as_ref().unwrap().authentication_key.clone(),
                    sequence_number: self.account.as_ref().unwrap().sequence_number,
                    sent_events_key: self.sent_events_key.clone().unwrap().0,
                    received_events_key: self.received_events_key.clone().unwrap().0,
                    balances,
                };

                let account_data_b64 = base64::encode(&bcs::to_bytes(&account_info).unwrap());
                let _resp = pr.query(DIEM_CONTRACT_ID, QueryReqData::AccountData { account_data_b64 }).await?;

                if account_info.sequence_number > 0 {
                    // Init sent events
                    let mut batch = JsonRpcBatch::new();
                    let sent_events_key = account_view.sent_events_key.0.clone();
                    batch.add_get_events_request(sent_events_key.to_string(), 0, account_view.sequence_number.clone());
                    let responses = self.rpc_client.execute(batch).unwrap();
                    match get_response_from_batch(0, &responses).unwrap().as_ref() {
                        Ok(resp) => {
                            self.sent_events = Option::from(EventView::vec_from_response(resp.clone()).unwrap());
                        },
                        Err(_) => {
                            println!("get sending events error");
                        }
                    }

                    // Init received events
                    let mut batch = JsonRpcBatch::new();
                    let received_events_key = account_view.received_events_key.0.clone();
                    batch.add_get_events_request(received_events_key.to_string(), 0, account_view.sequence_number.clone());
                    let responses = self.rpc_client.execute(batch).unwrap();
                    match get_response_from_batch(0, &responses).unwrap().as_ref() {
                        Ok(resp) => {
                            self.received_events = Option::from(EventView::vec_from_response(resp.clone()).unwrap());
                        },
                        Err(_) => {
                            println!("get receiving events error");
                        }
                    }
                }

                // Init transactions
                let mut batch = JsonRpcBatch::new();
                batch.add_get_account_transactions_request(self.account.as_ref().unwrap().address.clone(),
                    0, self.account.as_ref().unwrap().sequence_number.clone(), true);
                let responses = self.rpc_client.execute(batch).unwrap();
                match get_response_from_batch(0, &responses).unwrap().as_ref() {
                    Ok(resp) => {
                        let mut need_sync_transactions: Vec<TransactionView> = Vec::new();
                        let transactions = TransactionView::vec_from_response(resp.clone()).unwrap();
                        for transaction in transactions.clone() {
                            let exist = self.transactions.as_ref().is_some()
                                && self.transactions.as_ref().unwrap().iter().any(|x| x.version == transaction.version);
                            if !exist {
                                println!("new transaction!");
                                need_sync_transactions.push(transaction);
                            }
                        }

                        if need_sync_transactions.len() > 0 {
                            let _ = self.init_state();
                            for transaction in need_sync_transactions {
                                match self.get_transaction_proof(&transaction) {
                                    Ok(transaction_with_proof) => {
                                        println!("transaction_with_proof:{:?}", transaction_with_proof);

                                        let transaction_with_proof_b64 = base64::encode(&bcs::to_bytes(&transaction_with_proof).unwrap());
                                        let _resp = pr.query(DIEM_CONTRACT_ID, QueryReqData::VerifyTransaction
                                            { account_address: account_address.clone(), transaction_with_proof_b64 }).await?;
                                    },
                                    Err(_) => {
                                        println!("get_transaction_proof error");
                                    }
                                }
                            }
                        } else {
                            println!("no new transactions");
                        }

                        self.transactions = Option::from(transactions);
                    },
                    Err(_) => {
                        println!("get account's transactions error");
                    }
                }
            },
            None => {
                println!("get account view error");
            }
        }

        //println!("account: {:#?}", self.account);
        //println!("sent_events: {:#?}", self.sent_events);
        //println!("received_events: {:#?}", self.received_events);
        //println!("transactions: {:#?}", self.transactions);

        Ok(())
    }

    fn get_transaction_proof(
        &mut self,
        transaction: &TransactionView,
    ) -> Result<TransactionWithProof, Error> {
        let mut batch = JsonRpcBatch::new();
        let account = self.account.as_ref().unwrap().address.clone();
        batch.add_get_account_state_with_proof_request(
            account,
            Some(transaction.version),
            Some(self.trusted_state.as_ref().unwrap().latest_version()));
        let responses = self.rpc_client.execute(batch).unwrap();
        println!("responses:{:?}", responses);
        match get_response_from_batch(0, &responses).unwrap().as_ref() {
            Ok(resp) => {
                let account_state_proof =
                    AccountStateWithProofView::from_response(resp.clone()).unwrap();

                let ledger_info_to_transaction_info_proof: TransactionAccumulatorProof =
                    bcs::from_bytes(&account_state_proof.proof.ledger_info_to_transaction_info_proof.into_bytes().unwrap()).unwrap();
                let transaction_info: TransactionInfo =
                    bcs::from_bytes(&account_state_proof.proof.transaction_info.into_bytes().unwrap()).unwrap();
                let transaction_info_to_account_proof: SparseMerkleProof =
                    bcs::from_bytes(&account_state_proof.proof.transaction_info_to_account_proof.into_bytes().unwrap()).unwrap();
                let account_state_blob: AccountStateBlob =
                    bcs::from_bytes(&account_state_proof.blob.unwrap().into_bytes().unwrap()).unwrap();
                //println!("hash: {:}", transaction_info.transaction_hash.to_hex());
                if transaction_info.transaction_hash.to_hex() != transaction.hash {
                    println!("Bad transaction hash");
                    return Err(Error::BadTransactionHash);
                }
                let transaction_info_with_proof = TransactionInfoWithProof::new(
                    ledger_info_to_transaction_info_proof.clone(),
                    transaction_info.clone()
                );

                let account_transaction_state_proof = AccountStateProof::new(
                    transaction_info_with_proof.clone(),
                    transaction_info_to_account_proof.clone(),
                );
                let _ = account_transaction_state_proof.verify(
                    self.latest_li.as_ref().unwrap().ledger_info(),
                    transaction.version,
                    self.account.as_ref().unwrap().address.hash(),
                    Some(&account_state_blob),
                );
                println!("Transaction was verified");

                let state_proof = TransactionWithProof {
                    transaction_bytes: transaction.bytes.clone().into_bytes().unwrap(),
                    epoch_change_proof: self.epoch_change_proof.clone().unwrap(),
                    ledger_info_with_signatures: self.latest_li.clone().unwrap(),
                    ledger_info_to_transaction_info_proof,
                    transaction_info,
                    transaction_info_to_account_proof,
                    account_state_blob,
                    version: transaction.version,
                };

                return Ok(state_proof);
            },
            Err(_) => {
                println!("Failed to get account's state with proof");
                return Err(Error::FailedToGetResponse);
            }
        }
    }
}

async fn bridge(args: Args) -> Result<(), Error> {
    let mut demo = DiemDemo::new(&args.diem_rpc_endpoint).unwrap();

    let pr = PrClient::new(&args.pruntime_endpoint);

    //hard code Alice account
    let addr: String = "0xd4f0c053205ba934bb2ac0c4e8479e77".to_string();

    loop {
        let _= demo.init_account(&pr, addr.clone()).await;

        println!("Waiting for next loop");
        tokio::time::delay_for(std::time::Duration::from_millis(60000)).await;
    }
}

#[tokio::main]
async fn main() {
    let args = Args::from_args();
    let r = bridge(args).await;
    println!("bridge() exited with result: {:?}", r);
}