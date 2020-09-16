use reqwest::{Client, ClientBuilder, Error};
use serde_json::{json, Value};
use std::{collections::HashSet, convert::TryFrom, fmt, time::Duration};

/// Various constants for the JSON RPC client implementation
const JSON_RPC_VERSION: &str = "2.0";
const JSON_RPC_ID: u64 = 101;

#[derive(Clone)]
pub struct JsonRpcAsyncClinet {
    url: String,
    client: Client,
}

impl JsonRpcAsyncClinet {
    pub fn new(url: &str) ->Self {
        Self {
            url: url.to_string(),
            client: ClientBuilder::new()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("Unable to build Client."),
        }
    }
    pub async fn get_account(
        &self,
        address: &str
    ) -> Result<Value , Error> {
        let req_json = serde_json::json!({
            "jsonrpc": JSON_RPC_VERSION,
            "method": "get_account",
            "params": [address],
            "id": JSON_RPC_ID
        });

        let resp_json: serde_json::Value = self.client
            .post(&self.url)
            .json(&req_json)
            .send()
            .await?
            .json()
            .await?;
        Ok(resp_json)
    }

    pub async fn get_account_state_with_proof(
        &self,
        address: &str,
        from_version: &u64,
        to_version: &u64,
    ) -> Result<serde_json::Value , reqwest::Error> {
        let req_json = serde_json::json!({
            "jsonrpc": JSON_RPC_VERSION,
            "method": "get_account_state_with_proof",
            "params": [address, from_version, to_version],
            "id": JSON_RPC_ID
        });
        let resp_json: serde_json::Value = self.client
            .post(&self.url)
            .json(&req_json)
            .send()
            .await?
            .json()
            .await?;
        Ok(resp_json)
    }

    pub async fn get_state_proof(
        &self,
        known_version: &u64,
    ) -> Result<serde_json::Value , reqwest::Error> {
        let req_json = serde_json::json!({
            "jsonrpc": JSON_RPC_VERSION,
            "method": "get_state_proof",
            "params": [known_version],
            "id": JSON_RPC_ID
        });
        let resp_json: serde_json::Value = self.client
            .post(&self.url)
            .json(&req_json)
            .send()
            .await?
            .json()
            .await?;
        Ok(resp_json)
    }

    pub async fn get_currencies(
        &self,
    ) -> Result<serde_json::Value , reqwest::Error> {
        let req_json = serde_json::json!({
            "jsonrpc": JSON_RPC_VERSION,
            "method": "get_currencies",
            "params": [],
            "id": JSON_RPC_ID
        });
        let resp_json: serde_json::Value = self.client
            .post(&self.url)
            .json(&req_json)
            .send()
            .await?
            .json()
            .await?;
        Ok(resp_json)
    }

    pub async fn get_events(
        &self,
        event_key: &str,
        start: &u64,
        limit: &u64,
    ) -> Result<serde_json::Value , reqwest::Error> {
        let req_json = serde_json::json!({
            "jsonrpc": JSON_RPC_VERSION,
            "method": "get_events",
            "params": [event_key, start, limit],
            "id": JSON_RPC_ID
        });
        let resp_json: serde_json::Value = self.client
            .post(&self.url)
            .json(&req_json)
            .send()
            .await?
            .json()
            .await?;
        Ok(resp_json)
    }

    pub async fn get_account_transaction(
        &self,
        account: &str,
        sequence: &u64,
        include_events: bool,
    ) -> Result<serde_json::Value , reqwest::Error>{
        let req_json = serde_json::json!({
            "jsonrpc": JSON_RPC_VERSION,
            "method": "get_account_transaction",
            "params": [account, sequence, include_events],
            "id": JSON_RPC_ID
        });
        let resp_json: serde_json::Value = self.client
            .post(&self.url)
            .json(&req_json)
            .send()
            .await?
            .json()
            .await?;
        Ok(resp_json)
    }
}