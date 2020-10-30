use libra_client::{
    client::{
        LibraClient,
    },
    AccountData,
    AccountStatus,
};
use rand::{rngs::OsRng, Rng, SeedableRng};
use anyhow::{bail, ensure, Result};
use libra_logger::prelude::*;
use reqwest::Url;
use libra_crypto::{hash::{CryptoHash, HashValue}, ed25519::{Ed25519PrivateKey, Ed25519PublicKey, }, Uniform, test_utils::KeyPair, ValidCryptoMaterialStringExt};
use swiss_knife::generator::{
    GenerateRawTxnRequest, GenerateRawTxnResponse,
    GenerateSignedTxnRequest, GenerateSignedTxnResponse,
    SignTransactionUsingEd25519Request, SignTransactionUsingEd25519Response,
    generate_raw_txn, generate_signed_txn, sign_transaction_using_ed25519,
};

use libra_types::{
    access_path::AccessPath,
    account_address::{
        AccountAddress,
        from_public_key,
    },
    account_config::{
        from_currency_code_string, libra_root_address, testnet_dd_account_address,
        treasury_compliance_account_address, type_tag_for_currency_code,
        ACCOUNT_RECEIVED_EVENT_PATH, ACCOUNT_SENT_EVENT_PATH, LBR_NAME,
    },
    account_state::AccountState,
    chain_id::ChainId,
    ledger_info::LedgerInfoWithSignatures,
    transaction::{
        TransactionInfo,
        authenticator::AuthenticationKey,
        helpers::{create_unsigned_txn, create_user_txn, TransactionSigner},
        parse_transaction_argument, Module, RawTransaction, Script, SignedTransaction,
        TransactionArgument, TransactionPayload, Version, WriteSetPayload,
    },
    epoch_change::EpochChangeProof,
    epoch_state::EpochState,
    proof::{
        AccountStateProof,
        TransactionInfoWithProof,
        TransactionAccumulatorProof,
        SparseMerkleProof,
        AccumulatorConsistencyProof,
    },
    trusted_state::{TrustedState, TrustedStateChange},
    waypoint::Waypoint,
};
use libra_json_rpc_client::{
    get_response_from_batch,
    views::{
        AccountStateWithProofView, AccountView, BlockMetadata, BytesView, CurrencyInfoView,
        EventView, StateProofView, TransactionView,
    },
    JsonRpcBatch, JsonRpcClient, JsonRpcResponse, ResponseAsView,
};
use std::{convert::TryFrom, sync::Arc, io};
use libra_json_rpc_types::views::AmountView;
use libra_types::proof::AccumulatorProof;
use libra_types::account_state_blob::{AccountStateWithProof, AccountStateBlob};
use rustyline::{config::CompletionType, error::ReadlineError, Config, Editor};
use std::ops::Add;


pub struct LibraDemo {
    chain_id: ChainId,
    rpc_client: JsonRpcClient,
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
impl LibraDemo {
    pub fn new(url: &str) -> Result<Self> {
        let rpc_client = JsonRpcClient::new(Url::parse(url).unwrap()).unwrap();
        Ok(LibraDemo {
            chain_id: ChainId::new(2),
            rpc_client,
            sent_events_key: None,
            received_events_key: None,
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

    pub fn verify_state_proof(
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
                info!(
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
                    info!("Verified version change to: {}", new_state.latest_version());
                }
                self.trusted_state = Option::from(new_state);
            }
            TrustedStateChange::NoChange => (),
        }
        Ok(())
    }

    pub fn generate_account(
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

    pub fn generate_transaction(
        &mut self
    ) -> Result<()> {
        let tx_json = serde_json::json!({
            "txn_params": {
            "sender_address": "0xe1b3d22871989e9fd9dc6814b2f4fc41",
            "sequence_number": 42,
            "max_gas_amount": 1000000,
            "gas_unit_price": 0,
            "gas_currency_code": "LBR",
            "chain_id": "TESTING",
            "expiration_timestamp_secs": 1593189628
          },
          "script_params": {
            "peer_to_peer_transfer": {
              "coin_tag": "LBR",
              "recipient_address": "0x71e931795d23e9634fd24a5992065f6b",
              "amount": 100,
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
            public_key: self.account.as_ref().unwrap().key_pair.as_ref().unwrap().private_key.to_encoded_string().unwrap().clone(),
            signature: s_resp.signature.clone(),
        };
        let gs_resp:GenerateSignedTxnResponse = generate_signed_txn(gs_res);

        println!("{:#?}", gs_resp.signed_txn);
        Ok(())
    }

    pub fn init_state(
        &mut self
    ) -> Result<()> {
        let mut batch = JsonRpcBatch::new();
        batch.add_get_state_proof_request(0);

        let responses = self.rpc_client.execute(batch).unwrap();

        let resp = get_response_from_batch(0, &responses).unwrap().as_ref().unwrap();

        let mut state_proof = StateProofView::from_response(resp.clone()).unwrap();
        let epoch_change_proof: EpochChangeProof =
            lcs::from_bytes(&state_proof.epoch_change_proof.into_bytes().unwrap()).unwrap();
        let ledger_info_with_signatures: LedgerInfoWithSignatures =
            lcs::from_bytes(&state_proof.ledger_info_with_signatures.into_bytes().unwrap()).unwrap();

        let ledger_consistency_proof: AccumulatorConsistencyProof =
            lcs::from_bytes(&state_proof.ledger_consistency_proof.into_bytes().unwrap()).unwrap();
        // Init zero version state
        let zero_ledger_info_with_sigs = epoch_change_proof.ledger_info_with_sigs[0].clone();

        self.latest_epoch_change_li = Option::from(zero_ledger_info_with_sigs.clone());
        self.trusted_state = Option::from(TrustedState::try_from(zero_ledger_info_with_sigs.ledger_info()).unwrap());
        self.latest_li = Option::from(ledger_info_with_signatures.clone());

        // Update Latest version state
        self.verify_state_proof(ledger_info_with_signatures, epoch_change_proof);
        println!("{:#?}", self.trusted_state);
        println!("{:#?}", self.latest_li);
        Ok(())
    }


    pub fn init_account(
        &mut self
    ) -> Result<()> {
        // Init acoount information
        let mut batch = JsonRpcBatch::new();
        let mut address = AccountAddress::from_hex_literal("0x34a3675f875d8edeea6076ad1b560a11").unwrap();
        batch.add_get_account_request(address);
        let responses = self.rpc_client.execute(batch).unwrap();
        let resp = get_response_from_batch(0, &responses).unwrap().as_ref().unwrap();
        let op_account_view = AccountView::optional_from_response(resp.clone()).unwrap();
        // println!("{:#?}", op_account_view);
        let account_view = op_account_view.expect("AccountView deserialization error");
        self.account = Option::from(AccountData {
            address: address,
            authentication_key: account_view.authentication_key.into_bytes().ok(),
            key_pair: None,
            sequence_number: account_view.sequence_number,
            status: AccountStatus::Persisted,
        });
        self.sent_events_key = Option::from(account_view.sent_events_key.clone());
        self.received_events_key = Option::from(account_view.received_events_key.clone());
        self.balances = Option::from(account_view.balances.clone());

        // Init sent events
        let mut batch = JsonRpcBatch::new();
        let sent_events_key = account_view.sent_events_key.0.clone();
        batch.add_get_events_request(sent_events_key.to_string(), 0, account_view.sequence_number.clone());
        let responses = self.rpc_client.execute(batch).unwrap();
        let resp = get_response_from_batch(0, &responses).unwrap().as_ref().unwrap();
        self.sent_events = Option::from(EventView::vec_from_response(resp.clone()).unwrap());

        // Init revived events
        let mut batch = JsonRpcBatch::new();
        let received_events_key = account_view.received_events_key.0.clone();
        batch.add_get_events_request(received_events_key.to_string(), 0, account_view.sequence_number.clone());
        let responses = self.rpc_client.execute(batch).unwrap();
        let resp = get_response_from_batch(0, &responses).unwrap().as_ref().unwrap();
        self.received_events = Option::from(EventView::vec_from_response(resp.clone()).unwrap());

        // Init transactions
        let mut batch = JsonRpcBatch::new();
        batch.add_get_account_transactions_request(self.account.as_ref().unwrap().address.clone(),0, self.account.as_ref().unwrap().sequence_number.clone(), true);
        let responses = self.rpc_client.execute(batch).unwrap();
        let resp = get_response_from_batch(0, &responses).unwrap().as_ref().unwrap();
        self.transactions = Option::from(TransactionView::vec_from_response(resp.clone()).unwrap());

        // println!("{:#?}", self.account);
        // println!("{:#?}", self.sent_events);
        // println!("{:#?}", self.received_events);
        println!("{:#?}", self.transactions);
        Ok(())
    }

    pub fn verify_transactions(
        &mut self,
    ) -> Result<()> {
        let transactions= self.transactions.as_ref().unwrap().clone();
        for transaction in transactions {
            //println!("{:#?}", transaction);
            let mut batch = JsonRpcBatch::new();
            let mut account = self.account.as_ref().unwrap().address.clone();
            batch.add_get_account_state_with_proof_request(account, Some(transaction.version), Some(self.trusted_state.as_ref().unwrap().latest_version()));
            let responses = self.rpc_client.execute(batch).unwrap();
            let resp = get_response_from_batch(0, &responses).unwrap().as_ref().unwrap();
            let account_state_proof =
                AccountStateWithProofView::from_response(resp.clone()).unwrap();

            let ledger_info_to_transaction_info_proof: TransactionAccumulatorProof =
                lcs::from_bytes(&account_state_proof.proof.ledger_info_to_transaction_info_proof.into_bytes().unwrap()).unwrap();
            let transaction_info: TransactionInfo =
                lcs::from_bytes(&account_state_proof.proof.transaction_info.into_bytes().unwrap()).unwrap();
            let transaction_info_to_account_proof: SparseMerkleProof =
                lcs::from_bytes(&account_state_proof.proof.transaction_info_to_account_proof.into_bytes().unwrap()).unwrap();
            let account_state_blob: AccountStateBlob =
                lcs::from_bytes(&account_state_proof.blob.unwrap().into_bytes().unwrap()).unwrap();
            //println!("{:#?}", account_state_blob);


            let transaction_info_with_proof = TransactionInfoWithProof::new(
                ledger_info_to_transaction_info_proof,
                transaction_info
            );

            let account_transaction_state_proof = AccountStateProof::new(
                transaction_info_with_proof,
                transaction_info_to_account_proof,
            );
            account_transaction_state_proof.verify(
                self.latest_li.as_ref().unwrap().ledger_info(),
                transaction.version,
                self.account.as_ref().unwrap().address.hash(),
                Some(&account_state_blob),
            );
            println!("{:#?}", transaction.version);
        }
        Ok(())
    }

    pub fn unknown_cmd(
        &mut self,
    ) -> Result<()> {
        println!("unknown cmd");
        Ok(())
    }
}


fn main() {
    let mut input = String::new();
    print!("libra-demo:");

    let mut demo = LibraDemo::new("https://client.testnet.libra.org/v1").unwrap();
    let generate_account = String::from("generate account");
    let generate_transaction = String::from("generate transaction");
    let init_state = String::from("init state");
    let init_account = String::from("init account");
    let verify_transactions = String::from("verify transactions");
    let config = Config::builder()
        .history_ignore_space(true)
        .completion_type(CompletionType::List)
        .auto_add_history(true)
        .build();
    let mut rl = Editor::<()>::with_config(config);
    loop {
        let readline = rl.readline("libra% ");
        match readline {
            Ok(line) => {
                if line.eq(&generate_account) {
                    demo.generate_account();
                } else if line.eq(&generate_transaction) {
                    demo.generate_transaction();
                } else if line.eq(&init_state) {
                    demo.init_state();
                } else if line.eq(&init_account) {
                    demo.init_account();
                } else if line.eq(&verify_transactions) {
                    demo.verify_transactions();
                } else {
                    demo.unknown_cmd();
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("CTRL-C");
                break;
            }
            Err(ReadlineError::Eof) => {
                println!("CTRL-D");
                break;
            }
            Err(err) => {
                println!("Error: {:?}", err);
                break;
            }
        };
    }
}