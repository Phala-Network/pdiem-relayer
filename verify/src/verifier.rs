use hex::decode;
use lcs::from_bytes;
use types::{BytesView};

#[derive(Clone)]
pub struct StateProofVerfier {
    client_version: u64,
    ledger_info_with_signatures: String,
    epoch_change_proof: String,
}

impl StateProofVerfier {
    pub fn new(client_version: u64, ledger_info_with_signatures: &str, epoch_change_proof:&str) -> Self {
        Self {
            client_version,
            //ledger_info_with_signatures: lcs::from_bytes(hex::decode(ledger_info_with_signatures.to_string()).unwrap())
            epoch_change_proof: epoch_change_proof.to_string(),
        }
    }
    // pub fn verify_and_ratchet<'a>(
    //     &self,
    //     latest_li: &'a LedgerInfoWithSignatures,
    //     epoch_change_proof: &'a EpochChangeProof,
    // ) -> Result<TrustedStateChange<'a>> {
    //     let res_version = latest_li.ledger_info().version();
    //     ensure!(
    //         res_version >= self.latest_version(),
    //         "The target latest ledger info is stale and behind our current trusted version",
    //     );
    //
    //     if self
    //         .verifier
    //         .epoch_change_verification_required(latest_li.ledger_info().next_block_epoch())
    //     {
    //         // Verify the EpochChangeProof to move us into the latest epoch.
    //         let epoch_change_li = epoch_change_proof.verify(self.verifier.as_ref())?;
    //         let new_epoch_state = epoch_change_li
    //             .ledger_info()
    //             .next_epoch_state()
    //             .cloned()
    //             .ok_or_else(|| {
    //                 format_err!(
    //                     "A valid EpochChangeProof will never return a non-epoch change ledger info"
    //                 )
    //             })?;
    //
    //         // Verify the latest ledger info inside the latest epoch.
    //         let new_verifier = Arc::new(new_epoch_state);
    //
    //         // If these are the same, then we do not have a LI for the next Epoch and hence there
    //         // is nothing to verify.
    //         if epoch_change_li != latest_li {
    //             new_verifier.verify(latest_li)?;
    //         }
    //
    //         let new_state = TrustedState {
    //             verified_state: Waypoint::new_any(latest_li.ledger_info()),
    //             verifier: new_verifier,
    //         };
    //
    //         Ok(TrustedStateChange::Epoch {
    //             new_state,
    //             latest_epoch_change_li: epoch_change_li,
    //         })
    //     } else {
    //         // The EpochChangeProof is empty, stale, or only gets us into our
    //         // current epoch. We then try to verify that the latest ledger info
    //         // is this epoch.
    //         let new_waypoint = Waypoint::new_any(latest_li.ledger_info());
    //         if new_waypoint.version() == self.verified_state.version() {
    //             ensure!(
    //                 new_waypoint == self.verified_state,
    //                 "LedgerInfo doesn't match verified state"
    //             );
    //             Ok(TrustedStateChange::NoChange)
    //         } else {
    //             self.verifier.verify(latest_li)?;
    //
    //             let new_state = TrustedState {
    //                 verified_state: new_waypoint,
    //                 verifier: self.verifier.clone(),
    //             };
    //
    //             Ok(TrustedStateChange::Version { new_state })
    //         }
    //     }
    // }

    pub fn verify_epoch_change_proof() -> Result<bool> {

    }

    pub fn verify_ledger_info_with_signatures() -> Result<bool>{

    }
}

#[derive(Clone)]
pub struct LedgerProofVerfier {
    client_version: u64,
    ledger_info_with_signatures: String,
    epoch_change_proof: String,
}