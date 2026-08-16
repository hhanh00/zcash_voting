//! Precomputation APIs for delegation inputs.
//!
//! Prepared delegation bundles warm witnesses, padded-note secret initialization,
//! and PIR-backed nullifier proofs through `PreparedDelegationBundle::precompute`.
//! Lower-level helpers remain available for callers that already persisted
//! intermediate state.
//!
//! See the `zcash-voting-wallet-example` workspace crate for caller-oriented
//! precompute orchestration that can evolve independently from the library API.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
};

use crate::{
    round::VotingDb,
    types::{NoteInfo, VotingError, WitnessData},
};

use crate::{delegate::PreparedDelegationReport, round::BundleLayout, types::Network};

pub use crate::vote::VanWitness;

static VOTE_TREE_SYNCS: OnceLock<Mutex<HashMap<String, Arc<crate::tree_sync::VoteTreeSync>>>> =
    OnceLock::new();

/// Result of PIR precomputation for one delegation bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PirPrecomputeReport {
    pub cached: u32,
    pub fetched: u32,
}

/// Verifies a shielded note witness against its stored root.
///
/// Returns `Ok(())` when the witness recomputes to the expected root and
/// [`VotingError::InvalidInput`] when the bytes are malformed or mismatched.
pub fn verify_witness(witness: &WitnessData) -> Result<(), VotingError> {
    if crate::witness::verify_witness(witness)? {
        Ok(())
    } else {
        Err(VotingError::InvalidInput {
            message: format!(
                "witness root mismatch at note position {}",
                witness.position
            ),
        })
    }
}

/// Syncs the vote commitment tree for one round and returns the latest height.
///
/// For each confirmed bundle that has not yet submitted a vote, this also
/// verifies that the confirmed event position contains its delegation VAN.
pub async fn sync_vote_tree(
    db: &VotingDb,
    round_id: &str,
    node_url: &str,
) -> Result<u32, VotingError> {
    vote_tree_sync_for(db)?.sync(db, round_id, node_url).await
}

/// Generates the VAN witness needed by `vote::commit`.
pub async fn van_witness(
    db: &VotingDb,
    round_id: &str,
    bundle_index: u32,
    anchor_height: u32,
) -> Result<VanWitness, VotingError> {
    vote_tree_sync_for(db)?
        .generate_van_witness(db, round_id, bundle_index, anchor_height)
        .await
}

/// Drops cached vote tree state for one round, or all rounds when `round_id` is empty.
pub async fn reset_vote_tree(db: &VotingDb, round_id: &str) -> Result<(), VotingError> {
    vote_tree_sync_for(db)?.reset(round_id).await
}

/// Drops cached vote tree state and, for round-scoped resets, clears locally
/// prepared unsigned delegation setup fields so interrupted Keystone requests
/// can be rebuilt safely. Imported delegation capabilities are preserved.
///
/// Round-scoped cleanup is mainly for the restart mid-signing case: if the app
/// dies after `build_governance_pczt` persisted `pczt_sighash` (and related
/// setup columns) but before the user finishes signing, the next startup tries
/// to rebuild the Keystone request and `store_delegation_data` refuses to
/// overwrite those fields. Clearing unsigned setup for that round lets setup
/// run again without touching bundles that already have Keystone signatures or
/// a stored `delegation_tx_hash`.
///
/// When `round_id` is empty, only the process-local vote tree cache is reset
/// account-wide; no persisted delegation setup columns are cleared.
pub async fn reset_voting_session_state(db: &VotingDb, round_id: &str) -> Result<(), VotingError> {
    reset_vote_tree(db, round_id).await?;
    if !round_id.is_empty() {
        db.clear_unsigned_delegation_setup_fields(round_id).await?;
    }
    Ok(())
}

fn vote_tree_sync_for(db: &VotingDb) -> Result<Arc<crate::tree_sync::VoteTreeSync>, VotingError> {
    let wallet_id = db.wallet_id();
    let mut guard = VOTE_TREE_SYNCS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .map_err(|e| VotingError::Internal {
            message: format!("vote tree sync registry lock poisoned: {e}"),
        })?;
    Ok(guard
        .entry(wallet_id)
        .or_insert_with(|| Arc::new(crate::tree_sync::VoteTreeSync::new()))
        .clone())
}

/// Fetches and persists PIR-backed IMT non-membership proofs for one bundle.
///
/// This must run after padded-note secrets have been initialized for the bundle.
pub async fn delegation_pir(
    db: &VotingDb,
    round_id: &str,
    bundle_index: u32,
    notes: &[NoteInfo],
    pir_client: &pir_client::PirClientBlocking,
    network: Network,
) -> Result<PirPrecomputeReport, VotingError> {
    let result = db
        .precompute_delegation_pir(round_id, bundle_index, notes, pir_client, network)
        .await?;
    Ok(PirPrecomputeReport {
        cached: result.cached_count,
        fetched: result.fetched_count,
    })
}

/// Initializes padded-note secrets and runs PIR precompute.
///
/// Witnesses must already be cached for `notes`. Prefer
/// `PreparedDelegationBundle::precompute` for the full warm-up path from
/// prepared bundle state.
///
/// # Errors
///
/// Failures come from padded-secret initialization or PIR precompute.
pub(crate) async fn warm_delegation_pir(
    db: &VotingDb,
    round_id: &str,
    bundle_index: u32,
    notes: &[NoteInfo],
    layout: BundleLayout,
    pir_client: &pir_client::PirClientBlocking,
    network: Network,
) -> Result<PreparedDelegationReport, VotingError> {
    db.ensure_padded_secrets(round_id, bundle_index, notes)
        .await?;
    let report = delegation_pir(db, round_id, bundle_index, notes, pir_client, network).await?;

    Ok(PreparedDelegationReport {
        report,
        layout,
        bundle_index,
    })
}

