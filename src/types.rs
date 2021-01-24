use serde::{Serialize, Deserialize, de::DeserializeOwned};

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
pub enum QueryReqData {
    AccountData { account_data_b64: String },
    VerifyTransaction { account_address: String, transaction_with_proof_b64: String },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum QueryRespData {
    AccountData { size: u32 },
    VerifyTransaction { total: u32, verified: bool },
}