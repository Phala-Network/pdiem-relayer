use serde::{Serialize, Deserialize, de::DeserializeOwned};
use codec::{Encode, Decode};
// Node Runtime
use crate::runtimes::PhalaNodeRuntime;
pub type Runtime = PhalaNodeRuntime;

// pRuntime APIs
#[derive(Serialize, Deserialize, Debug)]
pub struct Nonce {
    value: u32,
}

impl Nonce {
    pub fn new() -> Nonce {
        Nonce { value: rand::random::<u32>() }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RuntimeReq<T: Serialize> {
    pub input: T,
    pub nonce: Nonce,
}
impl<T: Serialize> RuntimeReq<T> {
    pub fn new(input: T) -> Self {
        Self { input: input, nonce: Nonce::new() }
    }
}

pub trait Resp {
    type Resp: DeserializeOwned;
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignedResp {
    pub payload: String,
    pub status: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Payload {
    Plain(String),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Query {
    pub contract_id: u32,
    pub nonce: u32,
    pub request: QueryReqData,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct QueryReq {
    pub query_payload: String,
}
impl Resp for QueryReq {
    type Resp = Payload;
}

#[derive(Serialize, Deserialize, Debug)]
pub enum CommandReqData {
    AccountData { account_data_b64: String },
    VerifyTransaction { account_address: String, transaction_with_proof_b64: String },
    SetTrustedState { trusted_state_b64: String },
    VerifyEpochProof { ledger_info_with_signatures_b64: String, epoch_change_proof_b64: String },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum QueryReqData {
    GetSignedTransactions { start: u64 },
    CurrentState,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum QueryRespData {
    GetSignedTransactions { queue_b64: String },
    CurrentState { state: State },
}

#[derive(Serialize, Deserialize, Debug, Clone, Encode, Decode)]
pub struct TransactionData {
    pub sequence: u64,
    pub address: Vec<u8>,
    pub signed_tx: Vec<u8>,
    pub new_account: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct State {
    pub queue_seq: u64,
    pub account_address: Vec<String>,
}
