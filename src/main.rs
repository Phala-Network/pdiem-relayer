use structopt::StructOpt;

use diem_client::{
    AccountData,
    AccountStatus,
};
use anyhow::{ensure, Result};
use reqwest::Url;
use diem_crypto::hash::CryptoHash;

use diem_types::{
    account_address::{
        AccountAddress,
    },
    chain_id::ChainId,
    ledger_info::LedgerInfoWithSignatures,
    transaction::TransactionInfo,
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
    JsonRpcBatch, JsonRpcClient, ResponseAsView, JsonRpcResponse,
};
use std::{convert::TryFrom};
use diem_json_rpc_types::views::AmountView;
use diem_types::account_state_blob::AccountStateBlob;

mod pruntime_client;
mod types;
mod error;

type PrClient = pruntime_client::PRuntimeClient;

const DIEM_CONTRACT_ID: u32 = 5;
const INTERVAL: u64 = 1_000 * 60 * 3;

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

pub struct DiemBridge {
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

impl DiemBridge {
    pub fn new(url: &str) -> Result<Self> {
        let rpc_client = JsonRpcClient::new(Url::parse(url).unwrap()).unwrap();
        Ok(DiemBridge {
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
        match self.trusted_state.as_mut().unwrap().verify_and_ratchet(&li, &epoch_change_proof)?
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

    pub fn init_state(
        &mut self
    ) -> Result<(), Error> {
        let mut batch = JsonRpcBatch::new();
        batch.add_get_state_proof_request(0);
        if let Ok(resp) = self.request_rpc(batch) {
            let state_proof = StateProofView::from_response(resp).unwrap();
            //println!("state_proof:\n{:?}", state_proof);

            let epoch_change_proof: EpochChangeProof =
                bcs::from_bytes(&state_proof.epoch_change_proof.into_bytes().unwrap()).unwrap();
            let ledger_info_with_signatures: LedgerInfoWithSignatures =
                bcs::from_bytes(&state_proof.ledger_info_with_signatures.into_bytes().unwrap()).unwrap();

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
        } else {
            println!("Failed to get init_state");
            Err(Error::FailedToInitState)
        }
    }

    async fn init_account(
        &mut self,
        pr: &PrClient,
        account_address: String,
    ) -> Result<(), Error> {
        let mut state_initiated = false;
        // Init account information
        let mut batch = JsonRpcBatch::new();
        let address = AccountAddress::from_hex_literal(&account_address).unwrap();
        batch.add_get_account_request(address);
        let resp = self.request_rpc(batch);
        if resp.is_err() {
            return Err(Error::FailedToGetResponse);
        }

        if let Some(account_view) = AccountView::optional_from_response(resp.unwrap()).unwrap() {
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

                // Init received events
                let mut batch = JsonRpcBatch::new();
                let received_events_key = account_view.received_events_key.0.clone();
                batch.add_get_events_request(received_events_key.to_string(), 0, account_view.sequence_number.clone());
                if let Ok(resp) = self.request_rpc(batch) {
                    let received_events = EventView::vec_from_response(resp.clone()).unwrap();
                    let mut new_events: Vec<EventView> = Vec::new();
                    for event in received_events.clone() {
                        let exist = self.received_events.as_ref().is_some()
                            && self.received_events.as_ref().unwrap().iter().any(|x| x.transaction_version == event.transaction_version);
                        if !exist {
                            println!("new received event!");
                            new_events.push(event);
                        }
                    }

                    if new_events.len() > 0 && !state_initiated {
                        if let Err(_) = self.init_state() {
                            return Err(Error::FailedToInitState);
                        }

                        state_initiated = true;
                    }

                    for event in new_events {
                        if let Ok(transaction) = self.get_transaction_by_version(event.transaction_version) {
                            println!("received transaction:{:?}", transaction);
                            if let Ok(transaction_with_proof) = self.get_transaction_proof(&transaction) {
                                println!("transaction_with_proof:{:?}", transaction_with_proof);

                                let transaction_with_proof_b64 = base64::encode(&bcs::to_bytes(&transaction_with_proof).unwrap());
                                let _resp = pr.query(DIEM_CONTRACT_ID, QueryReqData::VerifyTransaction
                                    { account_address: account_address.clone(), transaction_with_proof_b64 }).await?;
                            } else {
                                println!("get_transaction_proof error");
                            }
                        } else {
                            println!("get_transaction_by_version error");
                        }
                    }

                    self.received_events = Option::from(received_events);
                } else {
                    println!("get receiving events error");
                }
            }

            // Init transactions
            let mut batch = JsonRpcBatch::new();
            batch.add_get_account_transactions_request(self.account.as_ref().unwrap().address.clone(),
                0, self.account.as_ref().unwrap().sequence_number.clone(), false);
            if let Ok(resp) = self.request_rpc(batch) {
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

                if need_sync_transactions.len() > 0 && !state_initiated {
                    if let Err(_) = self.init_state() {
                        return Err(Error::FailedToInitState);
                    }

                    state_initiated = true;
                }

                for transaction in need_sync_transactions {
                    if let Ok(transaction_with_proof) = self.get_transaction_proof(&transaction) {
                        println!("transaction_with_proof:{:?}", transaction_with_proof);

                        let transaction_with_proof_b64 = base64::encode(&bcs::to_bytes(&transaction_with_proof).unwrap());
                        let _resp = pr.query(DIEM_CONTRACT_ID, QueryReqData::VerifyTransaction
                            { account_address: account_address.clone(), transaction_with_proof_b64 }).await?;
                    } else {
                        println!("get_transaction_proof error");
                    }
                }

                self.transactions = Option::from(transactions);
            } else {
                println!("get account's transactions error");
            }
        } else {
            println!("get account view error");
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
        if let Ok(resp) = self.request_rpc(batch) {
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

            Ok(state_proof)
        } else {
            println!("Failed to get account's state with proof");
            Err(Error::FailedToGetResponse)
        }
    }

    fn get_transaction_by_version(
        &mut self,
        version: u64
    ) -> Result<TransactionView, Error> {
        let mut batch = JsonRpcBatch::new();
        batch.add_get_transactions_request(version, 1, false);
        if let Ok(resp) = self.request_rpc(batch) {
            let transactions = TransactionView::vec_from_response(resp.clone()).unwrap();
            if transactions.len() == 0 {
                return Err(Error::NoTransaction);
            }
            Ok(transactions[0].clone())
        } else {
            Err(Error::FailedToGetTransaction)
        }
    }

    fn request_rpc(
        &mut self,
        batch: JsonRpcBatch
    ) -> Result<JsonRpcResponse, Error> {
        let responses: Vec<Result<JsonRpcResponse>> = self.rpc_client.execute(batch).unwrap_or(Vec::new());
        println!("rpc responses：{:?}\n", responses);
        if let Ok(resp) = get_response_from_batch(0, &responses) {
            if resp.is_ok() {
                Ok(resp.as_ref().unwrap().clone())
            } else {
                Err(Error::FailedToGetResponse)
            }
        } else {
            Err(Error::FailedToGetResponse)
        }
    }
}

async fn bridge(args: Args) -> Result<(), Error> {
    let mut demo = DiemBridge::new(&args.diem_rpc_endpoint).unwrap();

    let pr = PrClient::new(&args.pruntime_endpoint);

    //hard code Alice account
    let addr: String = "0xd4f0c053205ba934bb2ac0c4e8479e77".to_string();

    loop {
        let _= demo.init_account(&pr, addr.clone()).await;

        println!("Waiting for next loop");
        tokio::time::delay_for(std::time::Duration::from_millis(INTERVAL)).await;
    }
}

#[tokio::main]
async fn main() {
    let args = Args::from_args();
    let r = bridge(args).await;
    println!("bridge() exited with result: {:?}", r);
}