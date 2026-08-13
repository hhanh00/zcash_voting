use ff::PrimeField;
use pasta_curves::pallas;
use sqlx::{Connection as _, SqliteConnection as Connection};

use crate::named_params;
use crate::storage::sqlx_ext::{query_map, ConnectionExt, OptionalExtension};
use voting_circuits::delegation::ImtProofData;

use crate::storage::{KeystoneSignatureRecord, RoundPhase, RoundState, RoundSummary, VoteRecord};
use crate::types::{
    Network, NoteInfo, ShareDelegationRecord, VotingError, VotingRoundParams, WitnessData,
};

const NOTE_IDENTITY_HASH_BYTES: usize = 32;
const NOTE_IDENTITY_DOMAIN: &[u8] = b"zcash-voting-note-identity-v1";

fn update_hash_with_len_prefixed_bytes(state: &mut blake2b_simd::State, value: &[u8]) {
    state.update(&(value.len() as u64).to_le_bytes());
    state.update(value);
}

fn note_identity_hash(note: &NoteInfo) -> [u8; NOTE_IDENTITY_HASH_BYTES] {
    let mut state = blake2b_simd::Params::new()
        .hash_length(NOTE_IDENTITY_HASH_BYTES)
        .to_state();
    // The domain string is longer than BLAKE2b's 16-byte personalization field.
    state.update(NOTE_IDENTITY_DOMAIN);
    state.update(&note.position.to_le_bytes());
    state.update(&note.value.to_le_bytes());
    state.update(&note.scope.to_le_bytes());
    update_hash_with_len_prefixed_bytes(&mut state, &note.commitment);
    update_hash_with_len_prefixed_bytes(&mut state, &note.nullifier);
    update_hash_with_len_prefixed_bytes(&mut state, &note.diversifier);
    update_hash_with_len_prefixed_bytes(&mut state, &note.rho);
    update_hash_with_len_prefixed_bytes(&mut state, &note.rseed);
    update_hash_with_len_prefixed_bytes(&mut state, note.ufvk_str.as_bytes());

    let hash = state.finalize();
    let mut out = [0u8; NOTE_IDENTITY_HASH_BYTES];
    out.copy_from_slice(hash.as_bytes());
    out
}

fn note_positions_blob(note_positions: &[u64]) -> Vec<u8> {
    note_positions
        .iter()
        .flat_map(|position| position.to_le_bytes())
        .collect()
}

fn note_positions_blob_for_notes(notes: &[NoteInfo]) -> Vec<u8> {
    notes
        .iter()
        .map(|note| note.position)
        .flat_map(|position| position.to_le_bytes())
        .collect()
}

fn note_identity_hashes_blob(notes: &[NoteInfo]) -> Vec<u8> {
    notes
        .iter()
        .flat_map(|note| note_identity_hash(note))
        .collect()
}

fn encode_gov_nullifiers_blob(gov_nullifiers: &[Vec<u8>]) -> Vec<u8> {
    gov_nullifiers
        .iter()
        .flat_map(|n| n.iter().copied())
        .collect()
}

fn encode_padded_note_secrets(padded_note_secrets: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    padded_note_secrets
        .iter()
        .flat_map(|(rho, rseed)| rho.iter().copied().chain(rseed.iter().copied()))
        .collect()
}

fn decode_padded_note_secrets(blob: Vec<u8>) -> Result<Vec<(Vec<u8>, Vec<u8>)>, VotingError> {
    if blob.len() % 64 != 0 {
        return Err(VotingError::Internal {
            message: format!(
                "corrupt padded_note_secrets blob: length {} is not a multiple of 64",
                blob.len()
            ),
        });
    }
    Ok(blob
        .chunks_exact(64)
        .map(|c| (c[..32].to_vec(), c[32..].to_vec()))
        .collect())
}

// --- Rounds ---

pub(crate) fn network_to_storage(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
        Network::Regtest => "regtest",
    }
}

pub(crate) fn network_from_storage(value: &str) -> Result<Network, VotingError> {
    match value {
        "mainnet" => Ok(Network::Mainnet),
        "testnet" => Ok(Network::Testnet),
        "regtest" => Ok(Network::Regtest),
        _ => Err(VotingError::Internal {
            message: format!("stored round network is invalid: {value}"),
        }),
    }
}

pub async fn insert_round(
    conn: &mut Connection,
    wallet_id: &str,
    network: Network,
    params: &VotingRoundParams,
    session_json: Option<&str>,
) -> Result<(), VotingError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    conn.execute(
        "INSERT INTO voting_rounds (round_id, wallet_id, network, snapshot_height, ea_pk, nc_root, nullifier_imt_root, session_json, phase, created_at)
         VALUES (:round_id, :wallet_id, :network, :snapshot_height, :ea_pk, :nc_root, :nullifier_imt_root, :session_json, :phase, :created_at)",
        named_params! {
            ":round_id": &params.vote_round_id,
            ":wallet_id": wallet_id,
            ":network": network_to_storage(network),
            ":snapshot_height": params.snapshot_height as i64,
            ":ea_pk": &params.ea_pk,
            ":nc_root": &params.nc_root,
            ":nullifier_imt_root": &params.nullifier_imt_root,
            ":session_json": session_json,
            ":phase": RoundPhase::Initialized as i32,
            ":created_at": now,
        },
    )
    .await
    .map_err(|e| VotingError::Internal {
        message: format!("failed to insert round: {}", e),
    })?;

    Ok(())
}

/// Set a round phase without checking lifecycle ordering.
///
/// Prefer `advance_round_phase` for normal workflow transitions.
#[deprecated(note = "use advance_round_phase to preserve forward-only round progression")]
pub async fn update_round_phase(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    phase: RoundPhase,
) -> Result<(), VotingError> {
    let rows = conn
        .execute(
            "UPDATE voting_rounds SET phase = :phase WHERE round_id = :round_id AND wallet_id = :wallet_id",
            named_params! {
                ":phase": phase as i32,
                ":round_id": round_id,
                ":wallet_id": wallet_id,
            },
        )
        .await
        .map_err(|e| VotingError::Internal {
            message: format!("failed to update round phase: {}", e),
        })?;

    if rows == 0 {
        return Err(VotingError::InvalidInput {
            message: format!("round not found: {}", round_id),
        });
    }

    Ok(())
}

/// Advance a round phase without allowing regressions.
///
/// Re-applying the current phase is treated as idempotent.
pub async fn advance_round_phase(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    phase: RoundPhase,
) -> Result<(), VotingError> {
    let requested_rank = phase as i32;
    let rows = conn
        .execute(
            "UPDATE voting_rounds
             SET phase = :phase
             WHERE round_id = :round_id
               AND wallet_id = :wallet_id
               AND phase < :phase",
            named_params! {
                ":phase": requested_rank,
                ":round_id": round_id,
                ":wallet_id": wallet_id,
            },
        )
        .await
        .map_err(|e| VotingError::Internal {
            message: format!("failed to advance round phase: {}", e),
        })?;
    if rows > 0 {
        return Ok(());
    }

    let current = get_round_state(conn, round_id, wallet_id).await?.phase;
    let current_rank = current as i32;

    // This can only happen if another connection changes the row between the
    // failed UPDATE and this readback.
    if current_rank < requested_rank {
        Err(VotingError::Internal {
            message: format!(
                "failed to advance round phase for {round_id}: current={current_rank}, requested={requested_rank}"
            ),
        })
    } else if current_rank > requested_rank {
        Err(VotingError::InvalidInput {
            message: format!(
                "refusing to regress round phase for {round_id}: current={current_rank}, requested={requested_rank}"
            ),
        })
    } else {
        Ok(())
    }
}

pub async fn load_round_params(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
) -> Result<VotingRoundParams, VotingError> {
    load_round_params_with_network(conn, round_id, wallet_id)
        .await
        .map(|(params, _)| params)
}

pub async fn load_round_params_with_network(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
) -> Result<(VotingRoundParams, Network), VotingError> {
    conn.query_row(
        "SELECT round_id, network, snapshot_height, ea_pk, nc_root, nullifier_imt_root FROM voting_rounds WHERE round_id = :round_id AND wallet_id = :wallet_id",
        named_params! { ":round_id": round_id, ":wallet_id": wallet_id },
        |row| {
            let network: String = row.get(1)?;
            Ok((
                VotingRoundParams {
                vote_round_id: row.get(0)?,
                    snapshot_height: row.get::<_, i64>(2)? as u64,
                    ea_pk: row.get(3)?,
                    nc_root: row.get(4)?,
                    nullifier_imt_root: row.get(5)?,
                },
                network,
            ))
        },
    )
    .await
    .map_err(|e| VotingError::InvalidInput {
        message: format!("round not found: {} ({})", round_id, e),
    })
    .and_then(|(params, network)| Ok((params, network_from_storage(&network)?)))
}

pub async fn load_round_network(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
) -> Result<Network, VotingError> {
    conn.query_row(
        "SELECT network FROM voting_rounds WHERE round_id = :round_id AND wallet_id = :wallet_id",
        named_params! { ":round_id": round_id, ":wallet_id": wallet_id },
        |row| row.get::<_, String>(0),
    )
    .await
    .map_err(|e| VotingError::InvalidInput {
        message: format!("round not found: {} ({})", round_id, e),
    })
    .and_then(|network| network_from_storage(&network))
}

pub async fn has_round(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
) -> Result<bool, VotingError> {
    conn.query_row(
        "SELECT 1 FROM voting_rounds WHERE round_id = :round_id AND wallet_id = :wallet_id LIMIT 1",
        named_params! { ":round_id": round_id, ":wallet_id": wallet_id },
        |_| Ok(()),
    )
    .await
    .optional()
    .map(|row| row.is_some())
    .map_err(|e| VotingError::Internal {
        message: format!("failed to check round existence: {}", e),
    })
}

pub async fn get_round_state(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
) -> Result<RoundState, VotingError> {
    let (phase_int, network, snapshot_height): (i32, String, i64) = conn
        .query_row(
            "SELECT phase, network, snapshot_height FROM voting_rounds WHERE round_id = :round_id AND wallet_id = :wallet_id",
            named_params! { ":round_id": round_id, ":wallet_id": wallet_id },
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .await
        .map_err(|e| VotingError::InvalidInput {
            message: format!("round not found: {} ({})", round_id, e),
        })?;
    let network = network_from_storage(&network)?;

    // proof_generated is true only when ALL bundles are locally proven or
    // capability-imported AND all bundles have a VAN leaf position. This keeps
    // the legacy UI field false until every delegation transaction lands.
    let bundle_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM voting_bundles WHERE round_id = :round_id AND wallet_id = :wallet_id",
            named_params! { ":round_id": round_id, ":wallet_id": wallet_id },
            |row| row.get(0),
        )
        .await
        .map_err(|e| VotingError::Internal {
            message: format!("failed to count bundles: {}", e),
        })?;

    let proof_generated = if bundle_count == 0 {
        false
    } else {
        let proven_count: i64 = conn
            .query_row(
                "SELECT COUNT(*)
                 FROM voting_bundles b
                 WHERE b.round_id = :round_id AND b.wallet_id = :wallet_id
                   AND (
                       EXISTS (
                           SELECT 1 FROM voting_proofs p
                           WHERE p.round_id = b.round_id
                             AND p.wallet_id = b.wallet_id
                             AND p.bundle_index = b.bundle_index
                             AND p.success = 1
                       )
                       OR (
                           b.note_positions_blob IS NULL
                           AND b.van_comm_rand IS NOT NULL
                           AND b.gov_comm IS NOT NULL
                           AND b.total_note_value IS NOT NULL
                           AND b.address_index = 0
                           AND b.delegation_tx_hash IS NOT NULL
                       )
                   )",
                named_params! { ":round_id": round_id, ":wallet_id": wallet_id },
                |row| row.get(0),
            )
            .await
            .map_err(|e| VotingError::Internal {
                message: format!("failed to count completed delegations: {}", e),
            })?;

        let van_positions_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM voting_bundles WHERE round_id = :round_id AND wallet_id = :wallet_id AND van_leaf_position IS NOT NULL",
                named_params! { ":round_id": round_id, ":wallet_id": wallet_id },
                |row| row.get(0),
            )
            .await
            .map_err(|e| VotingError::Internal {
                message: format!("failed to count VAN positions: {}", e),
            })?;

        proven_count >= bundle_count && van_positions_count >= bundle_count
    };

    Ok(RoundState {
        round_id: round_id.to_string(),
        phase: RoundPhase::from_i32(phase_int),
        network,
        snapshot_height: snapshot_height as u64,
        hotkey_address: None,
        delegated_weight: None,
        proof_generated,
    })
}

pub async fn list_rounds(
    conn: &mut Connection,
    wallet_id: &str,
) -> Result<Vec<RoundSummary>, VotingError> {
    let rounds = query_map(
        conn,
        "SELECT round_id, wallet_id, phase, network, snapshot_height, created_at FROM voting_rounds WHERE wallet_id = :wallet_id ORDER BY created_at DESC",
        named_params! { ":wallet_id": wallet_id },
        |row| {
            Ok(RoundSummary {
                round_id: row.get(0)?,
                wallet_id: row.get(1)?,
                phase: RoundPhase::from_i32(row.get(2)?),
                network: network_from_storage(&row.get::<_, String>(3)?)
                    .map_err(|e| sqlx::Error::Decode(Box::new(e)))?,
                snapshot_height: row.get::<_, i64>(4)? as u64,
                created_at: row.get::<_, i64>(5)? as u64,
            })
        },
    )
    .await
    .map_err(|e| VotingError::Internal {
        message: format!("failed to list rounds: {e}"),
    })?;

    Ok(rounds)
}

/// Delete a round and all associated data. Child tables (bundles, cached_tree_state,
/// proofs, witnesses, votes) are removed automatically via ON DELETE CASCADE.
pub async fn clear_round(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
) -> Result<(), VotingError> {
    conn.execute(
        "DELETE FROM voting_rounds WHERE round_id = :round_id AND wallet_id = :wallet_id",
        named_params! { ":round_id": round_id, ":wallet_id": wallet_id },
    )
    .await
    .map_err(|e| VotingError::Internal {
        message: format!("failed to clear round: {}", e),
    })?;
    Ok(())
}

// --- Bundles ---

/// Insert a bundle row from positions only.
///
/// Retained for SDK/FFI compatibility with callers that cannot provide full
/// notes at insertion time. Rows written this way have a NULL
/// `note_identity_hashes_blob`, so `require_bundle_notes` can only enforce the
/// legacy position check until callers migrate to `insert_bundle_notes`.
pub async fn insert_bundle(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
    note_positions: &[u64],
) -> Result<(), VotingError> {
    let positions_blob = note_positions_blob(note_positions);

    conn.execute(
        "INSERT INTO voting_bundles (round_id, wallet_id, bundle_index, note_positions_blob)
         VALUES (:round_id, :wallet_id, :bundle_index, :note_positions_blob)",
        named_params! {
            ":round_id": round_id,
            ":wallet_id": wallet_id,
            ":bundle_index": bundle_index as i64,
            ":note_positions_blob": positions_blob,
        },
    )
    .await
    .map_err(|e| VotingError::Internal {
        message: format!("failed to insert bundle: {}", e),
    })?;

    Ok(())
}

/// Insert a bundle row from full notes, persisting both positions and note identity hashes.
pub async fn insert_bundle_notes(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
    notes: &[NoteInfo],
) -> Result<(), VotingError> {
    let positions_blob = note_positions_blob_for_notes(notes);
    let identity_hashes_blob = note_identity_hashes_blob(notes);

    conn.execute(
        "INSERT INTO voting_bundles (round_id, wallet_id, bundle_index, note_positions_blob, note_identity_hashes_blob)
         VALUES (:round_id, :wallet_id, :bundle_index, :note_positions_blob, :note_identity_hashes_blob)",
        named_params! {
            ":round_id": round_id,
            ":wallet_id": wallet_id,
            ":bundle_index": bundle_index as i64,
            ":note_positions_blob": positions_blob,
            ":note_identity_hashes_blob": identity_hashes_blob,
        },
    )
    .await
    .map_err(|e| VotingError::Internal {
        message: format!("failed to insert bundle: {}", e),
    })?;

    Ok(())
}

fn decode_note_positions_blob(blob: &[u8]) -> Result<Vec<u64>, VotingError> {
    if blob.len() % 8 != 0 {
        return Err(VotingError::Internal {
            message: format!(
                "corrupt note_positions_blob: length {} is not a multiple of 8",
                blob.len()
            ),
        });
    }

    Ok(blob
        .chunks_exact(8)
        .map(|c| u64::from_le_bytes(c.try_into().expect("chunks_exact(8) guarantees 8 bytes")))
        .collect())
}

/// Get the number of bundles for a round.
pub async fn get_bundle_count(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
) -> Result<u32, VotingError> {
    conn.query_row(
        "SELECT COUNT(*) FROM voting_bundles WHERE round_id = :round_id AND wallet_id = :wallet_id",
        named_params! { ":round_id": round_id, ":wallet_id": wallet_id },
        |row| row.get::<_, i64>(0).map(|c| c as u32),
    )
    .await
    .map_err(|e| VotingError::Internal {
        message: format!("failed to get bundle count: {}", e),
    })
}

/// Imported bundles omit local note positions; local bundle insertion always stores them.
async fn round_has_imported_capability_bundles(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
) -> Result<bool, VotingError> {
    conn.query_row(
        "SELECT EXISTS (
             SELECT 1
             FROM voting_bundles
             WHERE round_id = :round_id
               AND wallet_id = :wallet_id
               AND note_positions_blob IS NULL
         )",
        named_params! { ":round_id": round_id, ":wallet_id": wallet_id },
        |row| row.get::<_, bool>(0),
    )
    .await
    .map_err(|e| VotingError::Internal {
        message: format!("failed to check for imported capability bundles: {e}"),
    })
}

/// Require every delegation in an imported capability round to be confirmed
/// before fresh vote state is created.
///
/// Locally prepared rounds retain their existing per-bundle voting behavior.
pub(crate) async fn require_capability_delegations_confirmed(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
) -> Result<(), VotingError> {
    if !round_has_imported_capability_bundles(conn, round_id, wallet_id).await? {
        return Ok(());
    }

    let pending_bundle = conn
        .query_row(
            "SELECT pending.bundle_index
             FROM voting_bundles pending
             WHERE pending.round_id = :round_id
               AND pending.wallet_id = :wallet_id
               AND pending.van_leaf_position IS NULL
             ORDER BY pending.bundle_index
             LIMIT 1",
            named_params! { ":round_id": round_id, ":wallet_id": wallet_id },
            |row| row.get::<_, i64>(0),
        )
        .await
        .optional()
        .map_err(|e| VotingError::Internal {
            message: format!("failed to check imported delegation confirmations: {e}"),
        })?;

    if let Some(bundle_index) = pending_bundle {
        return Err(VotingError::InvalidInput {
            message: format!(
                "imported capability round {round_id} cannot create votes until every delegation is confirmed; bundle {bundle_index} is still unconfirmed"
            ),
        });
    }

    Ok(())
}

/// Load the note positions for a specific bundle.
pub async fn load_bundle_note_positions(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
) -> Result<Vec<u64>, VotingError> {
    let blob: Vec<u8> = conn
        .query_row(
            "SELECT note_positions_blob FROM voting_bundles WHERE round_id = :round_id AND wallet_id = :wallet_id AND bundle_index = :bundle_index",
            named_params! {
                ":round_id": round_id,
                ":wallet_id": wallet_id,
                ":bundle_index": bundle_index as i64,
            },
            |row| row.get(0),
        )
        .await
        .map_err(|e| VotingError::InvalidInput {
            message: format!("bundle not found: round={}, bundle={} ({})", round_id, bundle_index, e),
        })?;

    decode_note_positions_blob(&blob)
}

pub async fn require_bundle_notes(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
    notes: &[NoteInfo],
) -> Result<(), VotingError> {
    let (positions_blob, identity_hashes_blob): (Vec<u8>, Option<Vec<u8>>) = conn
        .query_row(
            "SELECT note_positions_blob, note_identity_hashes_blob FROM voting_bundles WHERE round_id = :round_id AND wallet_id = :wallet_id AND bundle_index = :bundle_index",
            named_params! {
                ":round_id": round_id,
                ":wallet_id": wallet_id,
                ":bundle_index": bundle_index as i64,
            },
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .await
        .map_err(|e| VotingError::InvalidInput {
            message: format!(
                "bundle not found: round={}, bundle={} ({})",
                round_id, bundle_index, e
            ),
        })?;

    let stored_positions = decode_note_positions_blob(&positions_blob)?;
    let requested_positions = notes.iter().map(|note| note.position).collect::<Vec<_>>();
    if stored_positions != requested_positions {
        return Err(VotingError::InvalidInput {
            message: format!(
                "bundle_index {bundle_index} notes do not match persisted setup: stored positions {:?}, requested positions {:?}",
                stored_positions, requested_positions
            ),
        });
    }

    // Legacy carve-out: bundles persisted before 0.5.8 were ALTER-migrated to
    // v8 with a NULL `note_identity_hashes_blob` because the original
    // `NoteInfo` payloads cannot be backfilled. For those rows we fall back to
    // the position-only check above; identity verification only applies to
    // bundles set up under 0.5.8 or later.
    let Some(identity_hashes_blob) = identity_hashes_blob else {
        return Ok(());
    };

    if identity_hashes_blob.len() % NOTE_IDENTITY_HASH_BYTES != 0 {
        return Err(VotingError::Internal {
            message: format!(
                "corrupt note_identity_hashes_blob: length {} is not a multiple of {}",
                identity_hashes_blob.len(),
                NOTE_IDENTITY_HASH_BYTES
            ),
        });
    }

    let stored_hashes = identity_hashes_blob
        .chunks_exact(NOTE_IDENTITY_HASH_BYTES)
        .collect::<Vec<_>>();
    if stored_hashes.len() != notes.len() {
        return Err(VotingError::InvalidInput {
            message: format!(
                "bundle_index {bundle_index} note identity count mismatch: stored {}, requested {}",
                stored_hashes.len(),
                notes.len()
            ),
        });
    }

    for (index, (stored_hash, note)) in stored_hashes.iter().zip(notes.iter()).enumerate() {
        let requested_hash = note_identity_hash(note);
        if *stored_hash != requested_hash {
            return Err(VotingError::InvalidInput {
                message: format!(
                    "bundle_index {bundle_index} note identity mismatch at index {index}"
                ),
            });
        }
    }

    Ok(())
}

// --- Delegation Secrets ---
//
// After build_governance_pczt computes the VAN (governance commitment),
// we persist two values needed for later proof steps:
//   - van_comm_rand: the 32-byte blinding factor used in the VAN Poseidon hash.
//     Needed again in ZKP #2 (vote commitment) to reconstruct the VAN as a witness.
//   - dummy_nullifiers: nullifiers generated for zero-value padded note slots (§1.3.5).
//     Each is 32 bytes. Stored so the witness builder can reconstruct padded notes.

/// Persist all delegation action data and finalized TX1 effects in a single
/// UPDATE on the bundles table. The effects are required by
/// [`load_delegation_submission_data`].
pub async fn store_delegation_data(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
    van_comm_rand: &[u8],
    dummy_nullifiers: &[Vec<u8>],
    rho_signed: &[u8],
    padded_cmx: &[Vec<u8>],
    nf_signed: &[u8],
    cmx_new: &[u8],
    alpha: &[u8],
    rseed_signed: &[u8],
    rseed_output: &[u8],
    gov_comm: &[u8],
    total_note_value: u64,
    address_index: u32,
    padded_note_secrets: &[(Vec<u8>, Vec<u8>)],
    pczt_sighash: &[u8],
    tx1_effects: &[u8],
) -> Result<(), VotingError> {
    store_delegation_data_inner(
        conn,
        round_id,
        wallet_id,
        bundle_index,
        van_comm_rand,
        dummy_nullifiers,
        rho_signed,
        padded_cmx,
        nf_signed,
        cmx_new,
        alpha,
        rseed_signed,
        rseed_output,
        gov_comm,
        total_note_value,
        address_index,
        padded_note_secrets,
        pczt_sighash,
        Some(tx1_effects),
        None,
        None,
    )
    .await
}

/// Persist delegation action data, the finalized TX1 effects, and PCZT-derived
/// public inputs that the later delegation proof must reproduce.
pub(crate) async fn store_delegation_data_with_pczt_fields(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
    van_comm_rand: &[u8],
    dummy_nullifiers: &[Vec<u8>],
    rho_signed: &[u8],
    padded_cmx: &[Vec<u8>],
    nf_signed: &[u8],
    cmx_new: &[u8],
    alpha: &[u8],
    rseed_signed: &[u8],
    rseed_output: &[u8],
    gov_comm: &[u8],
    total_note_value: u64,
    address_index: u32,
    padded_note_secrets: &[(Vec<u8>, Vec<u8>)],
    pczt_sighash: &[u8],
    tx1_effects: &[u8],
    rk: &[u8],
    gov_nullifiers: &[Vec<u8>],
) -> Result<(), VotingError> {
    let gov_nullifiers_blob = encode_gov_nullifiers_blob(gov_nullifiers);
    store_delegation_data_inner(
        conn,
        round_id,
        wallet_id,
        bundle_index,
        van_comm_rand,
        dummy_nullifiers,
        rho_signed,
        padded_cmx,
        nf_signed,
        cmx_new,
        alpha,
        rseed_signed,
        rseed_output,
        gov_comm,
        total_note_value,
        address_index,
        padded_note_secrets,
        pczt_sighash,
        Some(tx1_effects),
        Some(rk),
        Some(gov_nullifiers_blob.as_slice()),
    )
    .await
}

async fn store_delegation_data_inner(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
    van_comm_rand: &[u8],
    dummy_nullifiers: &[Vec<u8>],
    rho_signed: &[u8],
    padded_cmx: &[Vec<u8>],
    nf_signed: &[u8],
    cmx_new: &[u8],
    alpha: &[u8],
    rseed_signed: &[u8],
    rseed_output: &[u8],
    gov_comm: &[u8],
    total_note_value: u64,
    address_index: u32,
    padded_note_secrets: &[(Vec<u8>, Vec<u8>)],
    pczt_sighash: &[u8],
    tx1_effects: Option<&[u8]>,
    rk: Option<&[u8]>,
    gov_nullifiers_blob: Option<&[u8]>,
) -> Result<(), VotingError> {
    if let Some(tx1_effects) = tx1_effects {
        crate::tx1::validate_tx1_effects(tx1_effects)?;
    }

    // Serialize padded-note nullifiers as a flat byte blob: [nf0 (32 bytes) | nf1 | nf2 | ...].
    // Length 0 means no padding was needed because all note slots were real.
    let dummy_blob: Vec<u8> = dummy_nullifiers
        .iter()
        .flat_map(|n| n.iter().copied())
        .collect();

    // Same flat-blob encoding for padded cmx values.
    let padded_blob: Vec<u8> = padded_cmx.iter().flat_map(|c| c.iter().copied()).collect();

    // Serialize padded_note_secrets as flat blob: N * 64 bytes (rho[32] || rseed[32] per entry).
    let secrets_blob = encode_padded_note_secrets(padded_note_secrets);

    let existing: Option<(Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>)> = conn
        .query_row(
            "SELECT padded_note_secrets, pczt_sighash, tx1_effects FROM voting_bundles \
             WHERE round_id = :round_id AND wallet_id = :wallet_id AND bundle_index = :bundle_index",
            named_params! {
                ":round_id": round_id,
                ":wallet_id": wallet_id,
                ":bundle_index": bundle_index as i64,
            },
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .await
        .optional()
        .map_err(|e| VotingError::Internal {
            message: format!("failed to load existing delegation data: {}", e),
        })?;
    let Some((existing_secrets, existing_sighash, existing_tx1_effects)) = existing else {
        return Err(VotingError::InvalidInput {
            message: format!(
                "bundle not found: round={}, bundle={}",
                round_id, bundle_index
            ),
        });
    };
    if let Some(existing_secrets) = existing_secrets {
        if existing_secrets != secrets_blob {
            return Err(VotingError::InvalidInput {
                message: format!(
                    "refusing to overwrite padded_note_secrets for round={}, bundle={}",
                    round_id, bundle_index
                ),
            });
        }
    }
    if let Some(existing_sighash) = existing_sighash {
        if existing_sighash != pczt_sighash {
            return Err(VotingError::InvalidInput {
                message: format!(
                    "refusing to overwrite pczt_sighash for round={}, bundle={}",
                    round_id, bundle_index
                ),
            });
        }
    }
    if let (Some(existing_tx1_effects), Some(tx1_effects)) = (existing_tx1_effects, tx1_effects) {
        if existing_tx1_effects != tx1_effects {
            return Err(VotingError::InvalidInput {
                message: format!(
                    "refusing to overwrite tx1_effects for round={}, bundle={}",
                    round_id, bundle_index
                ),
            });
        }
    }

    let rows = conn
        .execute(
            "UPDATE voting_bundles SET van_comm_rand = :rand, dummy_nullifiers = :dummies, \
             rho_signed = :rho, padded_note_data = :padded, nf_signed = :nf_signed, \
             cmx_new = :cmx_new, alpha = :alpha, rseed_signed = :rseed_signed, \
             rseed_output = :rseed_output, gov_comm = :gov_comm, \
             total_note_value = :total_note_value, address_index = :address_index, \
             padded_note_secrets = COALESCE(padded_note_secrets, :secrets), \
             pczt_sighash = COALESCE(pczt_sighash, :sighash), \
             tx1_effects = COALESCE(tx1_effects, :tx1_effects), \
             rk = COALESCE(:rk, rk), \
             gov_nullifiers_blob = COALESCE(:gov_nullifiers_blob, gov_nullifiers_blob) \
             WHERE round_id = :round_id AND wallet_id = :wallet_id AND bundle_index = :bundle_index",
            named_params! {
                ":rand": van_comm_rand,
                ":dummies": dummy_blob,
                ":rho": rho_signed,
                ":padded": padded_blob,
                ":nf_signed": nf_signed,
                ":cmx_new": cmx_new,
                ":alpha": alpha,
                ":rseed_signed": rseed_signed,
                ":rseed_output": rseed_output,
                ":gov_comm": gov_comm,
                ":total_note_value": total_note_value as i64,
                ":address_index": address_index as i64,
                ":secrets": secrets_blob,
                ":sighash": pczt_sighash,
                ":tx1_effects": tx1_effects,
                ":rk": rk,
                ":gov_nullifiers_blob": gov_nullifiers_blob,
                ":round_id": round_id,
                ":wallet_id": wallet_id,
                ":bundle_index": bundle_index as i64,
            },
        )
        .await
        .map_err(|e| VotingError::Internal {
            message: format!("failed to store delegation data: {}", e),
        })?;

    // If no rows were updated, the bundle doesn't exist.
    if rows == 0 {
        return Err(VotingError::InvalidInput {
            message: format!(
                "bundle not found: round={}, bundle={}",
                round_id, bundle_index
            ),
        });
    }

    Ok(())
}

/// Load nf_signed (signed note nullifier, 32 bytes) for a bundle.
pub async fn load_nf_signed(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
) -> Result<Vec<u8>, VotingError> {
    conn.query_row(
        "SELECT nf_signed FROM voting_bundles WHERE round_id = :round_id AND wallet_id = :wallet_id AND bundle_index = :bundle_index",
        named_params! { ":round_id": round_id, ":wallet_id": wallet_id, ":bundle_index": bundle_index as i64 },
        |row| row.get(0),
    )
    .await
    .map_err(|e| VotingError::InvalidInput {
        message: format!("no nf_signed for round={}, bundle={} ({})", round_id, bundle_index, e),
    })
}

/// Load cmx_new (output note commitment, 32 bytes) for a bundle.
pub async fn load_cmx_new(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
) -> Result<Vec<u8>, VotingError> {
    conn.query_row(
        "SELECT cmx_new FROM voting_bundles WHERE round_id = :round_id AND wallet_id = :wallet_id AND bundle_index = :bundle_index",
        named_params! { ":round_id": round_id, ":wallet_id": wallet_id, ":bundle_index": bundle_index as i64 },
        |row| row.get(0),
    )
    .await
    .map_err(|e| VotingError::InvalidInput {
        message: format!("no cmx_new for round={}, bundle={} ({})", round_id, bundle_index, e),
    })
}

/// Load alpha (spend auth randomizer scalar, 32 bytes) for a bundle.
pub async fn load_alpha(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
) -> Result<Vec<u8>, VotingError> {
    conn.query_row(
        "SELECT alpha FROM voting_bundles WHERE round_id = :round_id AND wallet_id = :wallet_id AND bundle_index = :bundle_index",
        named_params! { ":round_id": round_id, ":wallet_id": wallet_id, ":bundle_index": bundle_index as i64 },
        |row| row.get(0),
    )
    .await
    .map_err(|e| VotingError::InvalidInput {
        message: format!("no alpha for round={}, bundle={} ({})", round_id, bundle_index, e),
    })
}

/// Load signed note rseed (32 bytes) for a bundle.
pub async fn load_rseed_signed(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
) -> Result<Vec<u8>, VotingError> {
    conn.query_row(
        "SELECT rseed_signed FROM voting_bundles WHERE round_id = :round_id AND wallet_id = :wallet_id AND bundle_index = :bundle_index",
        named_params! { ":round_id": round_id, ":wallet_id": wallet_id, ":bundle_index": bundle_index as i64 },
        |row| row.get(0),
    )
    .await
    .map_err(|e| VotingError::InvalidInput {
        message: format!("no rseed_signed for round={}, bundle={} ({})", round_id, bundle_index, e),
    })
}

/// Load output note rseed (32 bytes) for a bundle.
pub async fn load_rseed_output(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
) -> Result<Vec<u8>, VotingError> {
    conn.query_row(
        "SELECT rseed_output FROM voting_bundles WHERE round_id = :round_id AND wallet_id = :wallet_id AND bundle_index = :bundle_index",
        named_params! { ":round_id": round_id, ":wallet_id": wallet_id, ":bundle_index": bundle_index as i64 },
        |row| row.get(0),
    )
    .await
    .map_err(|e| VotingError::InvalidInput {
        message: format!("no rseed_output for round={}, bundle={} ({})", round_id, bundle_index, e),
    })
}

/// Write padded note secrets once for a bundle, leaving an existing value intact.
pub async fn store_padded_note_secrets_if_absent(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
    padded_note_secrets: &[(Vec<u8>, Vec<u8>)],
) -> Result<(), VotingError> {
    let secrets_blob = encode_padded_note_secrets(padded_note_secrets);
    let rows = conn
        .execute(
            "UPDATE voting_bundles SET padded_note_secrets = :secrets \
             WHERE round_id = :round_id AND wallet_id = :wallet_id \
               AND bundle_index = :bundle_index AND padded_note_secrets IS NULL",
            named_params! {
                ":secrets": secrets_blob,
                ":round_id": round_id,
                ":wallet_id": wallet_id,
                ":bundle_index": bundle_index as i64,
            },
        )
        .await
        .map_err(|e| VotingError::Internal {
            message: format!("failed to store padded_note_secrets: {}", e),
        })?;

    if rows == 0 {
        let exists = conn
            .query_row(
                "SELECT 1 FROM voting_bundles WHERE round_id = :round_id AND wallet_id = :wallet_id AND bundle_index = :bundle_index",
                named_params! {
                    ":round_id": round_id,
                    ":wallet_id": wallet_id,
                    ":bundle_index": bundle_index as i64,
                },
                |_| Ok(()),
            )
            .await
            .optional()
            .map_err(|e| VotingError::Internal {
                message: format!("failed to check bundle existence: {}", e),
            })?
            .is_some();
        if !exists {
            return Err(VotingError::InvalidInput {
                message: format!(
                    "bundle not found: round={}, bundle={}",
                    round_id, bundle_index
                ),
            });
        }
    }

    Ok(())
}

/// Load padded note secrets if they have already been initialized for a bundle.
pub async fn load_padded_note_secrets_optional(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
) -> Result<Option<Vec<(Vec<u8>, Vec<u8>)>>, VotingError> {
    let blob: Option<Vec<u8>> = conn
        .query_row(
            "SELECT padded_note_secrets FROM voting_bundles WHERE round_id = :round_id AND wallet_id = :wallet_id AND bundle_index = :bundle_index",
            named_params! { ":round_id": round_id, ":wallet_id": wallet_id, ":bundle_index": bundle_index as i64 },
            |row| row.get(0),
        )
        .await
        .map_err(|e| VotingError::InvalidInput {
            message: format!("no padded_note_secrets for round={}, bundle={} ({})", round_id, bundle_index, e),
        })?;

    blob.map(decode_padded_note_secrets).transpose()
}

/// Load padded note secrets (rho + rseed pairs) for Phase 2 randomness threading.
/// Returns Vec of (rho[32], rseed[32]) pairs. Deserializes from flat 64-byte-per-entry blob.
pub async fn load_padded_note_secrets(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>, VotingError> {
    load_padded_note_secrets_optional(conn, round_id, wallet_id, bundle_index)
        .await?
        .ok_or_else(|| VotingError::InvalidInput {
            message: format!(
                "no padded_note_secrets for round={}, bundle={}",
                round_id, bundle_index
            ),
        })
}

/// Load the ZIP-244 sighash extracted from the PCZT (32 bytes).
pub async fn load_pczt_sighash(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
) -> Result<Vec<u8>, VotingError> {
    conn.query_row(
        "SELECT pczt_sighash FROM voting_bundles WHERE round_id = :round_id AND wallet_id = :wallet_id AND bundle_index = :bundle_index",
        named_params! { ":round_id": round_id, ":wallet_id": wallet_id, ":bundle_index": bundle_index as i64 },
        |row| row.get(0),
    )
    .await
    .map_err(|e| VotingError::InvalidInput {
        message: format!("no pczt_sighash for round={}, bundle={} ({})", round_id, bundle_index, e),
    })
}

/// Load the versioned Ironwood TX1 effecting data persisted at PCZT setup.
pub async fn load_tx1_effects(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
) -> Result<Vec<u8>, VotingError> {
    let effects: Vec<u8> = conn
        .query_row(
            "SELECT tx1_effects FROM voting_bundles WHERE round_id = :round_id AND wallet_id = :wallet_id AND bundle_index = :bundle_index",
            named_params! { ":round_id": round_id, ":wallet_id": wallet_id, ":bundle_index": bundle_index as i64 },
            |row| row.get(0),
        )
        .await
        .map_err(|e| VotingError::InvalidInput {
            message: format!(
                "no tx1_effects for round={}, bundle={} ({})",
                round_id, bundle_index, e
            ),
        })?;
    crate::tx1::validate_tx1_effects(&effects)?;
    Ok(effects)
}

/// Load the VAN blinding factor for a bundle. Needed as a private witness in ZKP #2.
pub async fn load_van_comm_rand(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
) -> Result<Vec<u8>, VotingError> {
    conn.query_row(
        "SELECT van_comm_rand FROM voting_bundles WHERE round_id = :round_id AND wallet_id = :wallet_id AND bundle_index = :bundle_index",
        named_params! { ":round_id": round_id, ":wallet_id": wallet_id, ":bundle_index": bundle_index as i64 },
        |row| row.get(0),
    )
    .await
    .map_err(|e| VotingError::InvalidInput {
        message: format!("no van_comm_rand for round={}, bundle={} ({})", round_id, bundle_index, e),
    })
}

/// Load dummy nullifiers for padded note slots. Returns 0-3 entries of 32 bytes each.
/// Deserializes the flat blob back into individual 32-byte nullifiers.
pub async fn load_dummy_nullifiers(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
) -> Result<Vec<Vec<u8>>, VotingError> {
    let blob: Vec<u8> = conn
        .query_row(
            "SELECT dummy_nullifiers FROM voting_bundles WHERE round_id = :round_id AND wallet_id = :wallet_id AND bundle_index = :bundle_index",
            named_params! { ":round_id": round_id, ":wallet_id": wallet_id, ":bundle_index": bundle_index as i64 },
            |row| row.get(0),
        )
        .await
        .map_err(|e| VotingError::InvalidInput {
            message: format!("no dummy_nullifiers for round={}, bundle={} ({})", round_id, bundle_index, e),
        })?;

    // Split the flat blob back into 32-byte chunks, one per dummy nullifier.
    if blob.len() % 32 != 0 {
        return Err(VotingError::Internal {
            message: format!(
                "corrupt dummy_nullifiers blob: length {} is not a multiple of 32",
                blob.len()
            ),
        });
    }
    Ok(blob.chunks_exact(32).map(|c| c.to_vec()).collect())
}

// --- Rho & Padded Note Data ---

/// Load rho_signed for a bundle (32-byte constrained rho).
pub async fn load_rho_signed(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
) -> Result<Vec<u8>, VotingError> {
    conn.query_row(
        "SELECT rho_signed FROM voting_bundles WHERE round_id = :round_id AND wallet_id = :wallet_id AND bundle_index = :bundle_index",
        named_params! { ":round_id": round_id, ":wallet_id": wallet_id, ":bundle_index": bundle_index as i64 },
        |row| row.get(0),
    )
    .await
    .map_err(|e| VotingError::InvalidInput {
        message: format!("no rho_signed for round={}, bundle={} ({})", round_id, bundle_index, e),
    })
}

/// Load padded note cmx data. Returns 0-3 entries of 32 bytes each.
pub async fn load_padded_cmx(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
) -> Result<Vec<Vec<u8>>, VotingError> {
    let blob: Vec<u8> = conn
        .query_row(
            "SELECT padded_note_data FROM voting_bundles WHERE round_id = :round_id AND wallet_id = :wallet_id AND bundle_index = :bundle_index",
            named_params! { ":round_id": round_id, ":wallet_id": wallet_id, ":bundle_index": bundle_index as i64 },
            |row| row.get(0),
        )
        .await
        .map_err(|e| VotingError::InvalidInput {
            message: format!("no padded_note_data for round={}, bundle={} ({})", round_id, bundle_index, e),
        })?;

    if blob.len() % 32 != 0 {
        return Err(VotingError::Internal {
            message: format!(
                "corrupt padded_note_data blob: length {} is not a multiple of 32",
                blob.len()
            ),
        });
    }
    Ok(blob.chunks_exact(32).map(|c| c.to_vec()).collect())
}

// --- ZKP #2 inputs ---

/// Data from delegation that ZKP #2 needs.
pub struct Zkp2DelegationData {
    pub gov_comm_rand: Vec<u8>,
    pub total_note_value: u64,
    pub address_index: u32,
    pub ea_pk: Vec<u8>,
    pub voting_round_id: String,
    /// Current proposal authority bitmask (starts at 0xFFFF, decremented per submitted vote).
    /// Bit `i` is set iff the voter has not yet cast a vote for proposal `i`.
    /// Since proposal IDs are 1-indexed (matching on-chain IDs), bit 0 is never
    /// cleared and acts as a structural invariant — it corresponds to the circuit's
    /// sentinel value rejected by the non-zero gate.
    pub proposal_authority: u64,
}

/// Initial authority bitmask: all 16 bits set. Bit 0 is the dead sentinel
/// (proposal_id=0 is rejected by the circuit); bits 1–15 are the usable slots.
const MAX_PROPOSAL_AUTHORITY: u64 = 65535;

/// Load all fields ZKP #2 needs from the bundles table (persisted during delegation).
/// Computes proposal_authority from submitted votes — each submitted vote clears its
/// proposal's bit, so the next vote's VAN reconstruction matches what's in the VC tree.
pub async fn load_zkp2_inputs(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
) -> Result<Zkp2DelegationData, VotingError> {
    let data = conn.query_row(
        "SELECT b.van_comm_rand, b.total_note_value, b.address_index, r.ea_pk, r.round_id \
         FROM voting_bundles b JOIN voting_rounds r ON b.round_id = r.round_id AND b.wallet_id = r.wallet_id \
         WHERE b.round_id = :round_id AND b.wallet_id = :wallet_id AND b.bundle_index = :bundle_index",
        named_params! { ":round_id": round_id, ":wallet_id": wallet_id, ":bundle_index": bundle_index as i64 },
        |row| {
            Ok(Zkp2DelegationData {
                gov_comm_rand: row.get(0)?,
                total_note_value: row.get::<_, i64>(1)? as u64,
                address_index: row.get::<_, i64>(2)? as u32,
                ea_pk: row.get(3)?,
                voting_round_id: row.get(4)?,
                proposal_authority: 0, // computed below
            })
        },
    )
    .await
    .map_err(|e| VotingError::InvalidInput {
        message: format!("failed to load ZKP2 inputs for round={}, bundle={} ({})", round_id, bundle_index, e),
    })?;

    // Compute current proposal_authority by clearing bits for votes with a
    // durable tx hash for THIS bundle specifically.
    let mut authority = MAX_PROPOSAL_AUTHORITY;
    let rows = query_map(
            conn,
            "SELECT proposal_id FROM voting_votes WHERE round_id = :round_id AND wallet_id = :wallet_id AND bundle_index = :bundle_index AND tx_hash IS NOT NULL",
            named_params! { ":round_id": round_id, ":wallet_id": wallet_id, ":bundle_index": bundle_index as i64 },
            |row| row.get::<_, i64>(0),
        )
        .await
        .map_err(|e| VotingError::Internal {
            message: format!("failed to query submitted votes: {}", e),
    })?;
    for row in rows {
        let pid = row as u64;
        authority &= !(1u64 << pid);
    }

    Ok(Zkp2DelegationData {
        proposal_authority: authority,
        ..data
    })
}

// --- VAN leaf position ---

/// Store the VAN leaf position after delegation TX is confirmed on chain.
///
/// Cast-vote confirmations should use `confirmation::confirm_vote_submission`
/// so the vote hash, successor VAN position, and VC position are recorded
/// atomically.
pub async fn store_van_position(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
    position: u32,
) -> Result<(), VotingError> {
    let rows = conn
        .execute(
            "UPDATE voting_bundles SET van_leaf_position = :position WHERE round_id = :round_id AND wallet_id = :wallet_id AND bundle_index = :bundle_index",
            named_params! {
                ":position": position as i64,
                ":round_id": round_id,
                ":wallet_id": wallet_id,
                ":bundle_index": bundle_index as i64,
            },
        )
        .await
        .map_err(|e| VotingError::Internal {
            message: format!("failed to store VAN position: {}", e),
        })?;
    if rows == 0 {
        return Err(VotingError::InvalidInput {
            message: format!(
                "bundle not found: round={}, bundle={}",
                round_id, bundle_index
            ),
        });
    }
    Ok(())
}

/// Load the VAN leaf position for witness generation.
pub async fn load_van_position(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
) -> Result<u32, VotingError> {
    conn.query_row(
        "SELECT van_leaf_position FROM voting_bundles WHERE round_id = :round_id AND wallet_id = :wallet_id AND bundle_index = :bundle_index",
        named_params! { ":round_id": round_id, ":wallet_id": wallet_id, ":bundle_index": bundle_index as i64 },
        |row| row.get::<_, Option<i64>>(0),
    )
    .await
    .map_err(|e| VotingError::InvalidInput {
        message: format!("no van_leaf_position for round={}, bundle={} ({})", round_id, bundle_index, e),
    })?
    .map(|v| v as u32)
    .ok_or_else(|| VotingError::InvalidInput {
        message: format!("van_leaf_position not yet set for round={}, bundle={}", round_id, bundle_index),
    })
}

/// One confirmed VAN position that must be retained during vote-tree sync.
pub(crate) struct VanTreeEntry {
    pub bundle_index: u32,
    pub position: u32,
    /// Present only while the delegation VAN is still the bundle's current VAN.
    pub expected_delegation_van: Option<pallas::Base>,
}

/// Loads confirmed VAN positions and expected delegation VANs that remain
/// current.
///
/// A submitted vote replaces the delegation VAN with a successor commitment,
/// so only bundles without a submitted vote can be checked against `gov_comm`.
pub(crate) async fn load_van_tree_entries(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
) -> Result<Vec<VanTreeEntry>, VotingError> {
    let rows = query_map(
        conn,
        "SELECT b.bundle_index, b.van_leaf_position, b.gov_comm,
                    EXISTS (
                        SELECT 1 FROM voting_votes v
                        WHERE v.round_id = b.round_id
                          AND v.wallet_id = b.wallet_id
                          AND v.bundle_index = b.bundle_index
                          AND v.tx_hash IS NOT NULL
                    )
             FROM voting_bundles b
             WHERE b.round_id = :round_id
               AND b.wallet_id = :wallet_id
               AND b.van_leaf_position IS NOT NULL
             ORDER BY b.bundle_index",
        named_params! { ":round_id": round_id, ":wallet_id": wallet_id },
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
                row.get::<_, i64>(3)? != 0,
            ))
        },
    )
    .await
    .map_err(|e| VotingError::Internal {
        message: format!("failed to query VAN tree entries: {e}"),
    })?;

    rows.into_iter()
        .map(|row| {
            let (bundle_index, position, commitment, has_submitted_vote) = row;
            let bundle_index = u32::try_from(bundle_index).map_err(|_| VotingError::Internal {
                message: "stored VAN bundle index does not fit in u32".to_string(),
            })?;
            let position = u32::try_from(position).map_err(|_| VotingError::Internal {
                message: format!(
                    "stored VAN position for bundle {bundle_index} does not fit in u32"
                ),
            })?;
            let expected_delegation_van = if has_submitted_vote {
                None
            } else {
                let commitment = commitment.ok_or_else(|| VotingError::Internal {
                    message: format!(
                        "confirmed delegation bundle {bundle_index} is missing its VAN commitment"
                    ),
                })?;
                Some(field_from_bytes(
                    &commitment,
                    &format!("bundle {bundle_index} VAN commitment"),
                )?)
            };
            Ok(VanTreeEntry {
                bundle_index,
                position,
                expected_delegation_van,
            })
        })
        .collect()
}

// --- Delegation proof result fields ---

fn require_matching_stored_field(
    stored: Option<&[u8]>,
    requested: &[u8],
    field: &str,
) -> Result<(), VotingError> {
    if let Some(stored) = stored {
        if stored != requested {
            return Err(VotingError::InvalidInput {
                message: format!("delegation proof result {field} does not match stored PCZT data"),
            });
        }
    }

    Ok(())
}

/// Persist public inputs from DelegationProofResult after proof generation.
/// If PCZT-derived values already exist, the proof result must reproduce them.
pub async fn store_proof_result_fields(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
    rk: &[u8],
    gov_nullifiers: &[Vec<u8>],
    nf_signed: &[u8],
    cmx_new: &[u8],
) -> Result<(), VotingError> {
    store_proof_result_fields_inner(
        conn,
        round_id,
        wallet_id,
        bundle_index,
        rk,
        gov_nullifiers,
        nf_signed,
        cmx_new,
        None,
    )
    .await
}

/// Persist proof public inputs and compare the proof VAN against the stored PCZT VAN.
pub(crate) async fn store_proof_result_fields_with_van_comm(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
    rk: &[u8],
    gov_nullifiers: &[Vec<u8>],
    nf_signed: &[u8],
    cmx_new: &[u8],
    van_comm: &[u8],
) -> Result<(), VotingError> {
    store_proof_result_fields_inner(
        conn,
        round_id,
        wallet_id,
        bundle_index,
        rk,
        gov_nullifiers,
        nf_signed,
        cmx_new,
        Some(van_comm),
    )
    .await
}

async fn store_proof_result_fields_inner(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
    rk: &[u8],
    gov_nullifiers: &[Vec<u8>],
    nf_signed: &[u8],
    cmx_new: &[u8],
    van_comm: Option<&[u8]>,
) -> Result<(), VotingError> {
    // Serialize gov_nullifiers as flat blob: [nf0 (32 bytes) | ... | nf4]
    let gov_nullifiers_blob = encode_gov_nullifiers_blob(gov_nullifiers);

    let (stored_rk, stored_gov_nullifiers, stored_nf_signed, stored_cmx_new, stored_gov_comm): (
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
    ) = conn
        .query_row(
            "SELECT rk, gov_nullifiers_blob, nf_signed, cmx_new, gov_comm \
             FROM voting_bundles \
             WHERE round_id = :round_id AND wallet_id = :wallet_id AND bundle_index = :bundle_index",
            named_params! {
                ":round_id": round_id,
                ":wallet_id": wallet_id,
                ":bundle_index": bundle_index as i64,
            },
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .await
        .map_err(|e| VotingError::InvalidInput {
            message: format!(
                "bundle not found: round={}, bundle={} ({})",
                round_id, bundle_index, e
            ),
        })?;

    require_matching_stored_field(stored_rk.as_deref(), rk, "rk")?;
    require_matching_stored_field(
        stored_gov_nullifiers.as_deref(),
        &gov_nullifiers_blob,
        "gov_nullifiers",
    )?;
    require_matching_stored_field(stored_nf_signed.as_deref(), nf_signed, "nf_signed")?;
    require_matching_stored_field(stored_cmx_new.as_deref(), cmx_new, "cmx_new")?;
    if let Some(van_comm) = van_comm {
        require_matching_stored_field(stored_gov_comm.as_deref(), van_comm, "van_comm")?;
    }

    let rows = conn
        .execute(
            "UPDATE voting_bundles SET rk = :rk, gov_nullifiers_blob = :gov_nullifiers_blob, \
             nf_signed = :nf_signed, cmx_new = :cmx_new \
             WHERE round_id = :round_id AND wallet_id = :wallet_id AND bundle_index = :bundle_index",
            named_params! {
                ":rk": rk,
                ":gov_nullifiers_blob": gov_nullifiers_blob,
                ":nf_signed": nf_signed,
                ":cmx_new": cmx_new,
                ":round_id": round_id,
                ":wallet_id": wallet_id,
                ":bundle_index": bundle_index as i64,
            },
        )
        .await
        .map_err(|e| VotingError::Internal {
            message: format!("failed to store proof result fields: {}", e),
        })?;

    if rows == 0 {
        return Err(VotingError::InvalidInput {
            message: format!(
                "bundle not found: round={}, bundle={}",
                round_id, bundle_index
            ),
        });
    }

    Ok(())
}

/// Raw delegation data loaded from DB for submission reconstruction.
pub struct DelegationDbFields {
    pub proof: Vec<u8>,
    pub rk: Vec<u8>,
    pub nf_signed: Vec<u8>,
    pub cmx_new: Vec<u8>,
    pub gov_comm: Vec<u8>,
    pub gov_nullifiers: Vec<Vec<u8>>,
    pub alpha: Vec<u8>,
    pub vote_round_id: String,
    pub tx1_effects: Vec<u8>,
}

/// Load all fields needed to reconstruct the chain-ready delegation TX payload.
pub async fn load_delegation_submission_data(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
) -> Result<DelegationDbFields, VotingError> {
    let (
        proof_bytes,
        rk,
        nf_signed,
        cmx_new,
        gov_comm,
        gov_nullifiers_blob,
        alpha,
        vote_round_id,
        tx1_effects,
    ): (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        String,
        Vec<u8>,
    ) = conn
        .query_row(
            "SELECT p.proof, b.rk, b.nf_signed, b.cmx_new, b.gov_comm, \
             b.gov_nullifiers_blob, b.alpha, b.round_id, b.tx1_effects \
             FROM voting_bundles b JOIN voting_proofs p ON b.round_id = p.round_id AND b.bundle_index = p.bundle_index AND b.wallet_id = p.wallet_id \
             WHERE b.round_id = :round_id AND b.wallet_id = :wallet_id AND b.bundle_index = :bundle_index AND p.success = 1",
            named_params! { ":round_id": round_id, ":wallet_id": wallet_id, ":bundle_index": bundle_index as i64 },
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                ))
            },
        )
        .await
        .map_err(|e| VotingError::InvalidInput {
            message: format!(
                "failed to load delegation submission data for round={}, bundle={} ({})",
                round_id, bundle_index, e
            ),
        })?;

    // Deserialize gov_nullifiers from flat blob back to Vec<Vec<u8>>
    if gov_nullifiers_blob.len() % 32 != 0 {
        return Err(VotingError::Internal {
            message: format!(
                "corrupt gov_nullifiers_blob: length {} is not a multiple of 32",
                gov_nullifiers_blob.len()
            ),
        });
    }
    let gov_nullifiers: Vec<Vec<u8>> = gov_nullifiers_blob
        .chunks_exact(32)
        .map(|c| c.to_vec())
        .collect();
    crate::tx1::validate_tx1_effects(&tx1_effects)?;

    Ok(DelegationDbFields {
        proof: proof_bytes,
        rk,
        nf_signed,
        cmx_new,
        gov_comm,
        gov_nullifiers,
        alpha,
        vote_round_id,
        tx1_effects,
    })
}

// --- Cached Tree State ---

pub async fn store_tree_state(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    snapshot_height: u64,
    tree_state: &[u8],
) -> Result<(), VotingError> {
    conn.execute(
        "INSERT OR REPLACE INTO voting_cached_tree_state (round_id, wallet_id, snapshot_height, tree_state)
         VALUES (:round_id, :wallet_id, :snapshot_height, :tree_state)",
        named_params! {
            ":round_id": round_id,
            ":wallet_id": wallet_id,
            ":snapshot_height": snapshot_height as i64,
            ":tree_state": tree_state,
        },
    )
    .await
    .map_err(|e| VotingError::Internal {
        message: format!("failed to store tree state: {}", e),
    })?;
    Ok(())
}

pub async fn load_tree_state(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
) -> Result<Vec<u8>, VotingError> {
    conn.query_row(
        "SELECT tree_state FROM voting_cached_tree_state WHERE round_id = :round_id AND wallet_id = :wallet_id",
        named_params! { ":round_id": round_id, ":wallet_id": wallet_id },
        |row| row.get(0),
    )
    .await
    .map_err(|e| VotingError::InvalidInput {
        message: format!("no cached tree state for round: {} ({})", round_id, e),
    })
}

// --- Witnesses (Merkle inclusion proofs for shielded notes) ---

/// Check if witnesses are already cached for a bundle.
pub async fn has_witnesses(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
) -> Result<bool, VotingError> {
    witness_count(conn, round_id, wallet_id, bundle_index)
        .await
        .map(|count| count > 0)
}

/// Count cached witnesses for a bundle.
pub async fn witness_count(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
) -> Result<usize, VotingError> {
    conn.query_row(
        "SELECT COUNT(*) FROM voting_witnesses WHERE round_id = :round_id AND wallet_id = :wallet_id AND bundle_index = :bundle_index",
        named_params! { ":round_id": round_id, ":wallet_id": wallet_id, ":bundle_index": bundle_index as i64 },
        |row| row.get::<_, i64>(0).map(|c| c as usize),
    )
    .await
    .map_err(|e| VotingError::Internal {
        message: format!("failed to check witnesses: {}", e),
    })
}

/// Store witness data for multiple notes in a bundle.
/// Each WitnessData's auth_path (Vec<Vec<u8>>) is serialized as a flat 1024-byte blob
/// (32 levels × 32 bytes each).
pub async fn store_witnesses(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
    witnesses: &[WitnessData],
) -> Result<(), VotingError> {
    insert_witnesses(conn, round_id, wallet_id, bundle_index, witnesses).await
}

async fn require_witness_positions_match_bundle(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
    witnesses: &[WitnessData],
) -> Result<(), VotingError> {
    let mut expected = load_bundle_note_positions(conn, round_id, wallet_id, bundle_index).await?;
    let mut actual = witnesses.iter().map(|w| w.position).collect::<Vec<_>>();
    expected.sort_unstable();
    actual.sort_unstable();

    if expected != actual {
        return Err(VotingError::InvalidInput {
            message: format!(
                "witness positions do not match bundle note positions for round={}, bundle={}: expected {:?}, got {:?}",
                round_id, bundle_index, expected, actual
            ),
        });
    }

    Ok(())
}

async fn insert_witnesses(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
    witnesses: &[WitnessData],
) -> Result<(), VotingError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    for w in witnesses {
        // Serialize auth_path as flat blob: 32 × 32 = 1024 bytes
        let auth_blob: Vec<u8> = w.auth_path.iter().flat_map(|h| h.iter().copied()).collect();

        conn.execute(
            "INSERT OR REPLACE INTO voting_witnesses (round_id, wallet_id, bundle_index, note_position, note_commitment, root, auth_path, created_at)
             VALUES (:round_id, :wallet_id, :bundle_index, :position, :commitment, :root, :auth_path, :created_at)",
            named_params! {
                ":round_id": round_id,
                ":wallet_id": wallet_id,
                ":bundle_index": bundle_index as i64,
                ":position": w.position as i64,
                ":commitment": &w.note_commitment,
                ":root": &w.root,
                ":auth_path": auth_blob,
                ":created_at": now,
            },
        )
        .await
        .map_err(|e| VotingError::Internal {
            message: format!("failed to store witness for position {}: {}", w.position, e),
        })?;
    }

    Ok(())
}

/// Atomically replace all cached witnesses for a bundle.
pub async fn replace_bundle_witnesses(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
    witnesses: &[WitnessData],
) -> Result<(), VotingError> {
    require_witness_positions_match_bundle(conn, round_id, wallet_id, bundle_index, witnesses)
        .await?;

    let mut tx = conn.begin().await.map_err(|e| VotingError::Internal {
        message: format!("failed to begin witness replacement transaction: {}", e),
    })?;

    (&mut *tx)
        .execute(
            "DELETE FROM voting_witnesses
         WHERE round_id = :round_id AND wallet_id = :wallet_id AND bundle_index = :bundle_index",
            named_params! {
                ":round_id": round_id,
                ":wallet_id": wallet_id,
                ":bundle_index": bundle_index as i64,
            },
        )
        .await
        .map_err(|e| VotingError::Internal {
            message: format!(
                "failed to clear witnesses for bundle {}: {}",
                bundle_index, e
            ),
        })?;

    insert_witnesses(&mut tx, round_id, wallet_id, bundle_index, witnesses).await?;

    tx.commit().await.map_err(|e| VotingError::Internal {
        message: format!("failed to commit witness replacement: {}", e),
    })
}

/// Load cached witnesses for a bundle, ordered by position.
pub async fn load_witnesses(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
) -> Result<Vec<crate::types::WitnessData>, VotingError> {
    let witnesses = query_map(
        conn,
            "SELECT note_position, note_commitment, root, auth_path FROM voting_witnesses
             WHERE round_id = :round_id AND wallet_id = :wallet_id AND bundle_index = :bundle_index ORDER BY note_position",
        named_params! { ":round_id": round_id, ":wallet_id": wallet_id, ":bundle_index": bundle_index as i64 },
        |row| {
            let position: i64 = row.get(0)?;
            let note_commitment: Vec<u8> = row.get(1)?;
            let root: Vec<u8> = row.get(2)?;
            let auth_blob: Vec<u8> = row.get(3)?;
            Ok((position as u64, note_commitment, root, auth_blob))
        },
    )
    .await
    .map_err(|e| VotingError::Internal {
        message: format!("failed to load witnesses: {e}"),
    })?;

    witnesses
        .into_iter()
        .map(|(position, note_commitment, root, auth_blob)| {
            // Deserialize auth_path from flat blob back to Vec<Vec<u8>>
            if auth_blob.len() != 32 * 32 {
                return Err(VotingError::Internal {
                    message: format!(
                        "corrupt auth_path blob for position {}: expected 1024 bytes, got {}",
                        position,
                        auth_blob.len()
                    ),
                });
            }
            let auth_path: Vec<Vec<u8>> = auth_blob.chunks_exact(32).map(|c| c.to_vec()).collect();

            Ok(crate::types::WitnessData {
                note_commitment,
                position,
                root,
                auth_path,
            })
        })
        .collect()
}

// --- PIR-backed IMT non-membership proof cache ---

fn field_to_bytes(value: pallas::Base) -> Vec<u8> {
    value.to_repr().to_vec()
}

fn field_from_bytes(bytes: &[u8], name: &str) -> Result<pallas::Base, VotingError> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| VotingError::Internal {
        message: format!("{name} must be 32 bytes, got {}", bytes.len()),
    })?;
    Option::from(pallas::Base::from_repr(arr)).ok_or_else(|| VotingError::Internal {
        message: format!("{name} is not a valid Pallas field element"),
    })
}

fn fields_to_blob(values: impl IntoIterator<Item = pallas::Base>) -> Vec<u8> {
    values
        .into_iter()
        .flat_map(|value| field_to_bytes(value).into_iter())
        .collect()
}

fn fields_from_blob<const N: usize>(
    blob: &[u8],
    name: &str,
) -> Result<[pallas::Base; N], VotingError> {
    let expected_len = N * 32;
    if blob.len() != expected_len {
        return Err(VotingError::Internal {
            message: format!("{name} must be {expected_len} bytes, got {}", blob.len()),
        });
    }

    let fields: Vec<pallas::Base> = blob
        .chunks_exact(32)
        .enumerate()
        .map(|(idx, chunk)| field_from_bytes(chunk, &format!("{name}[{idx}]")))
        .collect::<Result<_, _>>()?;

    fields.try_into().map_err(|_| VotingError::Internal {
        message: format!("{name} did not decode to {N} field elements"),
    })
}

pub async fn store_imt_proof(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
    nullifier: &[u8],
    proof: &ImtProofData,
) -> Result<(), VotingError> {
    let root = field_to_bytes(proof.root);
    let nf_bounds = fields_to_blob(proof.nf_bounds);
    let path = fields_to_blob(proof.path);

    conn.execute(
        "INSERT INTO voting_imt_proofs (round_id, wallet_id, bundle_index, nullifier, root, nf_bounds, leaf_pos, path, created_at)
         VALUES (:round_id, :wallet_id, :bundle_index, :nullifier, :root, :nf_bounds, :leaf_pos, :path, strftime('%s','now'))
         ON CONFLICT(round_id, wallet_id, bundle_index, nullifier)
         DO UPDATE SET root = :root, nf_bounds = :nf_bounds, leaf_pos = :leaf_pos, path = :path, created_at = strftime('%s','now')",
        named_params! {
            ":round_id": round_id,
            ":wallet_id": wallet_id,
            ":bundle_index": bundle_index as i64,
            ":nullifier": nullifier,
            ":root": root,
            ":nf_bounds": nf_bounds,
            ":leaf_pos": proof.leaf_pos as i64,
            ":path": path,
        },
    )
    .await
    .map_err(|e| VotingError::Internal {
        message: format!("failed to store IMT proof for bundle {bundle_index}: {e}"),
    })?;
    Ok(())
}

pub async fn load_imt_proof(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
    nullifier: &[u8],
    expected_root: &[u8],
) -> Result<Option<ImtProofData>, VotingError> {
    let row = conn
        .query_row(
            "SELECT root, nf_bounds, leaf_pos, path FROM voting_imt_proofs
             WHERE round_id = :round_id AND wallet_id = :wallet_id
               AND bundle_index = :bundle_index AND nullifier = :nullifier",
            named_params! {
                ":round_id": round_id,
                ":wallet_id": wallet_id,
                ":bundle_index": bundle_index as i64,
                ":nullifier": nullifier,
            },
            |row| {
                let root: Vec<u8> = row.get(0)?;
                let nf_bounds: Vec<u8> = row.get(1)?;
                let leaf_pos: i64 = row.get(2)?;
                let path: Vec<u8> = row.get(3)?;
                Ok((root, nf_bounds, leaf_pos, path))
            },
        )
        .await
        .optional()
        .map_err(|e| VotingError::Internal {
            message: format!("failed to load IMT proof for bundle {bundle_index}: {e}"),
        })?;

    let Some((root, nf_bounds, leaf_pos, path)) = row else {
        return Ok(None);
    };

    if root != expected_root {
        return Ok(None);
    }

    Ok(Some(ImtProofData {
        root: field_from_bytes(&root, "imt_proof.root")?,
        nf_bounds: fields_from_blob::<3>(&nf_bounds, "imt_proof.nf_bounds")?,
        leaf_pos: u32::try_from(leaf_pos).map_err(|_| VotingError::Internal {
            message: format!("invalid IMT proof leaf_pos {leaf_pos}"),
        })?,
        path: fields_from_blob::<29>(&path, "imt_proof.path")?,
    }))
}

// --- Proofs ---

pub async fn store_proof(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
    proof_bytes: &[u8],
) -> Result<(), VotingError> {
    conn.execute(
        "INSERT INTO voting_proofs (round_id, wallet_id, bundle_index, proof, success, created_at)
         VALUES (:round_id, :wallet_id, :bundle_index, :proof, 1, strftime('%s','now'))
         ON CONFLICT(round_id, wallet_id, bundle_index) DO UPDATE SET proof = :proof, success = 1",
        named_params! {
            ":proof": proof_bytes,
            ":round_id": round_id,
            ":wallet_id": wallet_id,
            ":bundle_index": bundle_index as i64,
        },
    )
    .await
    .map_err(|e| VotingError::Internal {
        message: format!("failed to store proof: {}", e),
    })?;
    Ok(())
}

// --- Votes ---

pub async fn store_vote(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
    proposal_id: u32,
    choice: u32,
    commitment: &[u8],
) -> Result<(), VotingError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    conn.execute_batch("SAVEPOINT store_vote_replace")
        .await
        .map_err(|e| VotingError::Internal {
            message: format!("failed to start store vote savepoint: {}", e),
        })?;

    let result: Result<(), VotingError> = async {
        let existing_vote: Option<(i64, Option<Vec<u8>>, bool)> = conn
            .query_row(
                "SELECT choice, commitment, tx_hash IS NOT NULL FROM voting_votes
                 WHERE round_id = :round_id
                   AND wallet_id = :wallet_id
                   AND bundle_index = :bundle_index
                   AND proposal_id = :proposal_id",
                named_params! {
                    ":round_id": round_id,
                    ":wallet_id": wallet_id,
                    ":bundle_index": bundle_index as i64,
                    ":proposal_id": proposal_id as i64,
                },
                |row| Ok((row.get(0)?, row.get(1)?, row.get::<_, i64>(2)? != 0)),
            )
            .await
            .optional()
            .map_err(|e| VotingError::Internal {
                message: format!("failed to load existing vote before store: {}", e),
            })?;
        let vote_changed = existing_vote
            .as_ref()
            .map(|(stored_choice, stored_commitment, _)| {
                *stored_choice != choice as i64 || stored_commitment.as_deref() != Some(commitment)
            })
            .unwrap_or(false);
        if let Some((_, _, true)) = existing_vote.as_ref() {
            if vote_changed {
                return Err(VotingError::InvalidInput {
                    message: format!(
                        "cannot replace submitted vote for round={}, wallet={}, bundle={}, proposal={}",
                        round_id, wallet_id, bundle_index, proposal_id
                    ),
                });
            }
            return Ok(());
        }
        if existing_vote.is_some() && !vote_changed {
            return Ok(());
        }

        conn.execute(
            "INSERT OR REPLACE INTO voting_votes (round_id, wallet_id, bundle_index, proposal_id, choice, commitment, created_at)
             VALUES (:round_id, :wallet_id, :bundle_index, :proposal_id, :choice, :commitment, :created_at)",
            named_params! {
                ":round_id": round_id,
                ":wallet_id": wallet_id,
                ":bundle_index": bundle_index as i64,
                ":proposal_id": proposal_id as i64,
                ":choice": choice as i64,
                ":commitment": commitment,
                ":created_at": now,
            },
        )
        .await
        .map_err(|e| VotingError::Internal {
            message: format!("failed to store vote: {}", e),
        })?;

        if vote_changed {
            conn.execute(
                "DELETE FROM voting_share_delegations
                 WHERE round_id = :round_id
                   AND wallet_id = :wallet_id
                   AND bundle_index = :bundle_index
                   AND proposal_id = :proposal_id",
                named_params! {
                    ":round_id": round_id,
                    ":wallet_id": wallet_id,
                    ":bundle_index": bundle_index as i64,
                    ":proposal_id": proposal_id as i64,
                },
            )
            .await
            .map_err(|e| VotingError::Internal {
                message: format!("failed to clear stale share delegations: {}", e),
            })?;
        }

        Ok(())
    }.await;

    match result {
        Ok(()) => conn
            .execute_batch("RELEASE SAVEPOINT store_vote_replace")
            .await
            .map_err(|e| VotingError::Internal {
                message: format!("failed to commit store vote savepoint: {}", e),
            }),
        Err(err) => {
            let _ = conn.execute_batch(
                "ROLLBACK TO SAVEPOINT store_vote_replace; RELEASE SAVEPOINT store_vote_replace",
            ).await;
            Err(err)
        }
    }
}

pub async fn clear_stale_share_delegations_for_intent(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    proposal_id: u32,
    skipped: bool,
    choice: Option<u32>,
) -> Result<u64, VotingError> {
    let rows = if skipped {
        conn.execute(
            "DELETE FROM voting_share_delegations
             WHERE round_id = :round_id
               AND wallet_id = :wallet_id
               AND proposal_id = :proposal_id",
            named_params! {
                ":round_id": round_id,
                ":wallet_id": wallet_id,
                ":proposal_id": proposal_id as i64,
            },
        )
        .await
    } else if let Some(choice) = choice {
        conn.execute(
            "DELETE FROM voting_share_delegations
             WHERE round_id = :round_id
               AND wallet_id = :wallet_id
               AND proposal_id = :proposal_id
               AND NOT EXISTS (
                   SELECT 1 FROM voting_votes
                   WHERE votes.round_id = share_delegations.round_id
                     AND votes.wallet_id = share_delegations.wallet_id
                     AND votes.bundle_index = share_delegations.bundle_index
                     AND votes.proposal_id = share_delegations.proposal_id
                     AND votes.choice = :choice
               )",
            named_params! {
                ":round_id": round_id,
                ":wallet_id": wallet_id,
                ":proposal_id": proposal_id as i64,
                ":choice": choice as i64,
            },
        )
        .await
    } else {
        Ok(0usize)
    }
    .map_err(|e| VotingError::Internal {
        message: format!("failed to clear stale share delegations: {}", e),
    })?;
    Ok(rows as u64)
}

pub async fn ensure_no_submitted_vote_conflict_for_intent(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    proposal_id: u32,
    skipped: bool,
    choice: Option<u32>,
) -> Result<(), VotingError> {
    let conflicting_bundle = conn
        .query_row(
            "SELECT bundle_index
             FROM voting_votes
             WHERE round_id = :round_id
               AND wallet_id = :wallet_id
               AND proposal_id = :proposal_id
               AND tx_hash IS NOT NULL
               AND (:skipped != 0 OR choice != :choice)
             ORDER BY bundle_index
             LIMIT 1",
            named_params! {
                ":round_id": round_id,
                ":wallet_id": wallet_id,
                ":proposal_id": proposal_id as i64,
                ":skipped": if skipped { 1_i64 } else { 0_i64 },
                ":choice": choice.map(|c| c as i64),
            },
            |row| row.get::<_, i64>(0),
        )
        .await
        .optional()
        .map_err(|e| VotingError::Internal {
            message: format!("failed to check submitted vote intent conflict: {}", e),
        })?;

    if let Some(bundle_index) = conflicting_bundle {
        return Err(VotingError::InvalidInput {
            message: format!(
                "round {round_id} bundle {bundle_index} proposal {proposal_id} has a submitted vote that conflicts with ballot intent"
            ),
        });
    }

    Ok(())
}

/// Get all votes for a round (across all bundles).
pub async fn get_votes(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
) -> Result<Vec<VoteRecord>, VotingError> {
    let votes = query_map(
            conn,
            "SELECT proposal_id, bundle_index, choice FROM voting_votes WHERE round_id = :round_id AND wallet_id = :wallet_id",
            named_params! { ":round_id": round_id, ":wallet_id": wallet_id },
            |row| {
                Ok(VoteRecord {
                    proposal_id: row.get::<_, i64>(0)? as u32,
                    bundle_index: row.get::<_, i64>(1)? as u32,
                    choice: row.get::<_, i64>(2)? as u32,
                })
            },
        )
        .await
        .map_err(|e| VotingError::Internal {
            message: format!("failed to get votes: {}", e),
        })?;

    Ok(votes)
}

/// Delete all local bundles (and their cascaded witnesses/proofs) with index >= `from_index`.
/// Used when the user skips remaining Keystone bundles — we remove the unsigned
/// bundle rows so that `proof_generated` (which counts ALL DB bundles) reflects
/// only the signed+proven bundles. Imported capability batches are atomic and
/// must instead be replaced with `clear_round` followed by a complete re-import.
pub async fn delete_bundles_from(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    from_index: u32,
) -> Result<u64, VotingError> {
    let mut tx = conn
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|e| VotingError::Internal {
            message: format!("failed to begin bundle deletion: {e}"),
        })?;
    if round_has_imported_capability_bundles(&mut tx, round_id, wallet_id).await? {
        return Err(VotingError::InvalidInput {
            message: format!(
                "imported capability round {round_id} cannot delete bundles independently; clear the round before importing a complete replacement capability"
            ),
        });
    }

    let rows = (&mut *tx)
        .execute(
            "DELETE FROM voting_bundles WHERE round_id = :round_id AND wallet_id = :wallet_id AND bundle_index >= :from_index",
            named_params! {
                ":round_id": round_id,
                ":wallet_id": wallet_id,
                ":from_index": from_index as i64,
            },
        )
        .await
        .map_err(|e| VotingError::Internal {
            message: format!("failed to delete bundles from index {}: {}", from_index, e),
        })?;
    tx.commit().await.map_err(|e| VotingError::Internal {
        message: format!("failed to commit bundle deletion: {e}"),
    })?;
    Ok(rows as u64)
}

// --- Recovery state: TX hashes ---

pub async fn store_delegation_tx_hash(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
    tx_hash: &str,
) -> Result<(), VotingError> {
    let rows = conn
        .execute(
            "UPDATE voting_bundles SET delegation_tx_hash = :tx_hash
             WHERE round_id = :round_id
               AND wallet_id = :wallet_id
               AND bundle_index = :bundle_index
               AND (delegation_tx_hash IS NULL OR delegation_tx_hash = :tx_hash)",
            named_params! {
                ":tx_hash": tx_hash,
                ":round_id": round_id,
                ":wallet_id": wallet_id,
                ":bundle_index": bundle_index as i64,
            },
        )
        .await
        .map_err(|e| VotingError::Internal {
            message: format!("failed to store delegation tx hash: {}", e),
        })?;
    if rows == 0 {
        if let Some(existing) =
            existing_delegation_tx_hash(conn, round_id, wallet_id, bundle_index).await?
        {
            if existing.as_deref() == Some(tx_hash) {
                return Ok(());
            }
            if existing.is_some() {
                return Err(VotingError::InvalidInput {
                    message: format!(
                        "delegation tx hash already recorded for round={}, wallet={}, bundle={}",
                        round_id, wallet_id, bundle_index
                    ),
                });
            }
        }
        return Err(VotingError::InvalidInput {
            message: format!(
                "no bundle found for round={}, wallet={}, bundle={}",
                round_id, wallet_id, bundle_index
            ),
        });
    }
    Ok(())
}

async fn existing_delegation_tx_hash(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
) -> Result<Option<Option<String>>, VotingError> {
    conn.query_row(
        "SELECT delegation_tx_hash
         FROM voting_bundles
         WHERE round_id = :round_id
           AND wallet_id = :wallet_id
           AND bundle_index = :bundle_index",
        named_params! {
            ":round_id": round_id,
            ":wallet_id": wallet_id,
            ":bundle_index": bundle_index as i64,
        },
        |row| row.get(0),
    )
    .await
    .optional()
    .map_err(|e| VotingError::Internal {
        message: format!("failed to load existing delegation tx hash: {}", e),
    })
}

pub async fn get_delegation_tx_hash(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
) -> Result<Option<String>, VotingError> {
    conn.query_row(
        "SELECT delegation_tx_hash FROM voting_bundles WHERE round_id = :round_id AND wallet_id = :wallet_id AND bundle_index = :bundle_index",
        named_params! {
            ":round_id": round_id,
            ":wallet_id": wallet_id,
            ":bundle_index": bundle_index as i64,
        },
        |row| row.get(0),
    )
    .await
    .map_err(|e| VotingError::Internal {
        message: format!("failed to get delegation tx hash: {}", e),
    })
}

pub async fn record_vote_submission(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
    proposal_id: u32,
    tx_hash: &str,
) -> Result<(), VotingError> {
    ensure_vote_submission_matches_ballot_intent(
        conn,
        round_id,
        wallet_id,
        bundle_index,
        proposal_id,
    )
    .await?;
    let rows = conn
        .execute(
            "UPDATE voting_votes SET tx_hash = :tx_hash
             WHERE round_id = :round_id
               AND wallet_id = :wallet_id
               AND bundle_index = :bundle_index
               AND proposal_id = :proposal_id
               AND (tx_hash IS NULL OR tx_hash = :tx_hash)
               AND (
                   NOT EXISTS (
                       SELECT 1 FROM voting_ballot_intent
                       WHERE round_id = :round_id
                         AND wallet_id = :wallet_id
                         AND proposal_id = :proposal_id
                   )
                   OR EXISTS (
                       SELECT 1 FROM voting_ballot_intent
                       WHERE round_id = :round_id
                         AND wallet_id = :wallet_id
                         AND proposal_id = :proposal_id
                         AND skipped = 0
                         AND choice = votes.choice
                   )
               )",
            named_params! {
                ":tx_hash": tx_hash,
                ":round_id": round_id,
                ":wallet_id": wallet_id,
                ":bundle_index": bundle_index as i64,
                ":proposal_id": proposal_id as i64,
            },
        )
        .await
        .map_err(|e| VotingError::Internal {
            message: format!("failed to record vote submission: {}", e),
        })?;
    if rows == 0 {
        ensure_vote_submission_matches_ballot_intent(
            conn,
            round_id,
            wallet_id,
            bundle_index,
            proposal_id,
        )
        .await?;
        if let Some(existing) =
            existing_vote_tx_hash(conn, round_id, wallet_id, bundle_index, proposal_id).await?
        {
            if existing.as_deref() == Some(tx_hash) {
                return Ok(());
            }
            if existing.is_some() {
                return Err(VotingError::InvalidInput {
                    message: format!(
                        "vote tx hash already recorded for round={}, wallet={}, bundle={}, proposal={}",
                        round_id, wallet_id, bundle_index, proposal_id
                    ),
                });
            }
        }
        return Err(VotingError::InvalidInput {
            message: format!(
                "no vote found for round={}, wallet={}, bundle={}, proposal={}",
                round_id, wallet_id, bundle_index, proposal_id
            ),
        });
    }
    Ok(())
}

async fn existing_vote_tx_hash(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
    proposal_id: u32,
) -> Result<Option<Option<String>>, VotingError> {
    conn.query_row(
        "SELECT tx_hash FROM voting_votes
         WHERE round_id = :round_id
           AND wallet_id = :wallet_id
           AND bundle_index = :bundle_index
           AND proposal_id = :proposal_id",
        named_params! {
            ":round_id": round_id,
            ":wallet_id": wallet_id,
            ":bundle_index": bundle_index as i64,
            ":proposal_id": proposal_id as i64,
        },
        |row| row.get(0),
    )
    .await
    .optional()
    .map_err(|e| VotingError::Internal {
        message: format!("failed to load existing vote tx hash: {}", e),
    })
}

pub async fn get_vote_tx_hash(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
    proposal_id: u32,
) -> Result<Option<String>, VotingError> {
    conn.query_row(
        "SELECT tx_hash FROM voting_votes WHERE round_id = :round_id AND wallet_id = :wallet_id AND bundle_index = :bundle_index AND proposal_id = :proposal_id",
        named_params! {
            ":round_id": round_id,
            ":wallet_id": wallet_id,
            ":bundle_index": bundle_index as i64,
            ":proposal_id": proposal_id as i64,
        },
        |row| row.get(0),
    )
    .await
    .map_err(|e| VotingError::Internal {
        message: format!("failed to get vote tx hash: {}", e),
    })
}

pub async fn get_commitment_bundle(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
    proposal_id: u32,
) -> Result<Option<(String, u64)>, VotingError> {
    let (json, pos): (Option<String>, Option<i64>) = conn.query_row(
        "SELECT commitment_bundle_json, vc_tree_position FROM voting_votes WHERE round_id = :round_id AND wallet_id = :wallet_id AND bundle_index = :bundle_index AND proposal_id = :proposal_id",
        named_params! {
            ":round_id": round_id,
            ":wallet_id": wallet_id,
            ":bundle_index": bundle_index as i64,
            ":proposal_id": proposal_id as i64,
        },
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .await
    .map_err(|e| VotingError::Internal {
        message: format!("failed to get commitment bundle: {}", e),
    })?;
    match (json, pos) {
        (Some(json), Some(pos)) => {
            let position = u64::try_from(pos).map_err(|_| VotingError::Internal {
                message: format!("stored vc_tree_position must be non-negative, got {pos}"),
            })?;
            Ok(Some((json, position)))
        }
        (Some(_), None) => Err(VotingError::Internal {
            message:
                "commitment bundle is stored without vc_tree_position; refusing to assume position 0"
                    .to_string(),
        }),
        (None, _) => Ok(None),
    }
}

/// Loads raw commitment-bundle recovery columns for one vote key.
///
/// This lenient reader returns nullable `commitment_bundle_json` and
/// `vc_tree_position` exactly as stored, so callers can distinguish in-progress
/// recovery rows from fully confirmed rows.
pub(crate) async fn get_commitment_bundle_recovery(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
    proposal_id: u32,
) -> Result<Option<(Option<String>, Option<i64>)>, VotingError> {
    conn.query_row(
        "SELECT commitment_bundle_json, vc_tree_position FROM voting_votes
         WHERE round_id = :round_id AND wallet_id = :wallet_id
           AND bundle_index = :bundle_index AND proposal_id = :proposal_id",
        named_params! {
            ":round_id": round_id,
            ":wallet_id": wallet_id,
            ":bundle_index": bundle_index as i64,
            ":proposal_id": proposal_id as i64,
        },
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .await
    .optional()
    .map_err(|e| VotingError::Internal {
        message: format!("failed to get commitment bundle recovery fields: {}", e),
    })
}

// --- Keystone signatures ---

pub async fn store_keystone_signature(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
    sig: &[u8],
    sighash: &[u8],
    rk: &[u8],
) -> Result<(), VotingError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    conn.execute(
        "INSERT OR REPLACE INTO voting_keystone_signatures (round_id, wallet_id, bundle_index, sig, sighash, rk, created_at) VALUES (:round_id, :wallet_id, :bundle_index, :sig, :sighash, :rk, :created_at)",
        named_params! {
            ":round_id": round_id,
            ":wallet_id": wallet_id,
            ":bundle_index": bundle_index as i64,
            ":sig": sig,
            ":sighash": sighash,
            ":rk": rk,
            ":created_at": now as i64,
        },
    )
    .await
    .map_err(|e| VotingError::Internal {
        message: format!("failed to store keystone signature: {}", e),
    })?;
    Ok(())
}

pub async fn get_keystone_signatures(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
) -> Result<Vec<KeystoneSignatureRecord>, VotingError> {
    query_map(
        conn,
            "SELECT bundle_index, sig, sighash, rk FROM voting_keystone_signatures WHERE round_id = :round_id AND wallet_id = :wallet_id ORDER BY bundle_index",
        named_params! { ":round_id": round_id, ":wallet_id": wallet_id },
        |row| {
            Ok(KeystoneSignatureRecord {
                bundle_index: row.get::<_, i64>(0)? as u32,
                sig: row.get(1)?,
                sighash: row.get(2)?,
                rk: row.get(3)?,
            })
        },
    )
        .await
        .map_err(|e| VotingError::Internal {
            message: format!("failed to query keystone signatures: {e}"),
        })
}

// --- Session reset cleanup ---

/// Clears locally prepared unsigned delegation setup fields for one round.
///
/// Imported capability bundles have no local note selection, so their NULL
/// `note_positions_blob` keeps their voting fields outside this cleanup.
pub async fn clear_unsigned_delegation_setup_fields(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
) -> Result<(), VotingError> {
    conn.execute(
        "UPDATE voting_bundles
         SET van_comm_rand = NULL,
             dummy_nullifiers = NULL,
             rho_signed = NULL,
             padded_note_data = NULL,
             nf_signed = NULL,
             cmx_new = NULL,
             alpha = NULL,
             rseed_signed = NULL,
             rseed_output = NULL,
             gov_comm = NULL,
             total_note_value = NULL,
             address_index = NULL,
             rk = NULL,
             gov_nullifiers_blob = NULL,
             padded_note_secrets = NULL,
             pczt_sighash = NULL,
             tx1_effects = NULL
         WHERE round_id = :round_id
           AND wallet_id = :wallet_id
           AND note_positions_blob IS NOT NULL
           AND delegation_tx_hash IS NULL
           AND van_leaf_position IS NULL
           AND bundle_index NOT IN (
               SELECT bundle_index
               FROM voting_keystone_signatures
               WHERE round_id = :round_id AND wallet_id = :wallet_id
           )",
        named_params! { ":round_id": round_id, ":wallet_id": wallet_id },
    )
    .await
    .map_err(|e| VotingError::Internal {
        message: format!("failed to clear unsigned delegation setup fields: {e}"),
    })?;
    Ok(())
}

// --- Recovery state cleanup ---

/// Clears retryable recovery state without erasing recorded confirmations or
/// imported delegation capabilities.
pub async fn clear_recovery_state(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
) -> Result<(), VotingError> {
    conn.execute(
        "DELETE FROM voting_share_delegations WHERE round_id = :round_id AND wallet_id = :wallet_id",
        named_params! { ":round_id": round_id, ":wallet_id": wallet_id },
    )
    .await
    .map_err(|e| VotingError::Internal {
        message: format!("failed to clear share delegations: {}", e),
    })?;
    conn.execute(
        "DELETE FROM voting_keystone_signatures WHERE round_id = :round_id AND wallet_id = :wallet_id",
        named_params! { ":round_id": round_id, ":wallet_id": wallet_id },
    )
    .await
    .map_err(|e| VotingError::Internal {
        message: format!("failed to clear keystone signatures: {}", e),
    })?;
    conn.execute(
        "UPDATE voting_bundles SET delegation_tx_hash = NULL
         WHERE round_id = :round_id
           AND wallet_id = :wallet_id
           AND note_positions_blob IS NOT NULL
           AND van_leaf_position IS NULL",
        named_params! { ":round_id": round_id, ":wallet_id": wallet_id },
    )
    .await
    .map_err(|e| VotingError::Internal {
        message: format!("failed to clear delegation tx hashes: {}", e),
    })?;
    conn.execute(
        "UPDATE voting_votes SET tx_hash = NULL, commitment_bundle_json = NULL
         WHERE round_id = :round_id
           AND wallet_id = :wallet_id
           AND vc_tree_position IS NULL",
        named_params! { ":round_id": round_id, ":wallet_id": wallet_id },
    )
    .await
    .map_err(|e| VotingError::Internal {
        message: format!("failed to clear vote recovery columns: {}", e),
    })?;
    Ok(())
}

// --- Share delegation tracking ---

/// Record a share delegation after sending to helper servers.
///
/// This raw SQL helper is crate-internal because callers must provide a
/// nullifier that matches the persisted vote recovery bundle. Wallet
/// integrations should use `share::record`, which derives that nullifier from
/// recovery state before storing the helper delivery state.
pub(crate) async fn record_share_delegation(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
    proposal_id: u32,
    share_index: u32,
    sent_to_urls: &[String],
    nullifier: &[u8],
    submit_at: u64,
) -> Result<(), VotingError> {
    ensure_share_matches_ballot_intent(conn, round_id, wallet_id, bundle_index, proposal_id)
        .await?;
    let urls_json = serde_json::to_string(sent_to_urls).map_err(|e| VotingError::Internal {
        message: format!("failed to serialize sent_to_urls: {}", e),
    })?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    conn.execute(
        "INSERT INTO voting_share_delegations \
         (round_id, wallet_id, bundle_index, proposal_id, share_index, sent_to_urls, nullifier, confirmed, submit_at, created_at) \
         VALUES (:round_id, :wallet_id, :bundle_index, :proposal_id, :share_index, :sent_to_urls, :nullifier, 0, :submit_at, :created_at) \
         ON CONFLICT (round_id, wallet_id, bundle_index, proposal_id, share_index) DO UPDATE SET \
         sent_to_urls = excluded.sent_to_urls, \
         submit_at = excluded.submit_at \
         WHERE share_delegations.nullifier = excluded.nullifier",
        named_params! {
            ":round_id": round_id,
            ":wallet_id": wallet_id,
            ":bundle_index": bundle_index,
            ":proposal_id": proposal_id,
            ":share_index": share_index,
            ":sent_to_urls": urls_json,
            ":nullifier": nullifier,
            ":submit_at": submit_at,
            ":created_at": now,
        },
    )
    .await
    .map_err(|e| VotingError::Internal {
        message: format!("failed to record share delegation: {}", e),
    })
    .and_then(|rows| {
        if rows == 0 {
            return Err(VotingError::InvalidInput {
                message: format!(
                    "share nullifier conflict for round={}, wallet={}, bundle={}, proposal={}, share={}",
                    round_id, wallet_id, bundle_index, proposal_id, share_index
                ),
            });
        }
        Ok(())
    })?;
    Ok(())
}

/// Load all share delegations for a round.
pub async fn get_share_delegations(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
) -> Result<Vec<ShareDelegationRecord>, VotingError> {
    load_share_delegations(
        conn,
        "SELECT bundle_index, proposal_id, share_index, sent_to_urls, nullifier, confirmed, submit_at, created_at, round_id \
         FROM voting_share_delegations WHERE round_id = :round_id AND wallet_id = :wallet_id \
         ORDER BY proposal_id, share_index",
        round_id,
        wallet_id,
    )
    .await
}

/// Load only unconfirmed share delegations for a round.
pub async fn get_unconfirmed_delegations(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
) -> Result<Vec<ShareDelegationRecord>, VotingError> {
    load_share_delegations(
        conn,
        "SELECT bundle_index, proposal_id, share_index, sent_to_urls, nullifier, confirmed, submit_at, created_at, round_id \
         FROM voting_share_delegations WHERE round_id = :round_id AND wallet_id = :wallet_id AND confirmed = 0 \
         ORDER BY proposal_id, share_index",
        round_id,
        wallet_id,
    )
    .await
}

async fn load_share_delegations(
    conn: &mut Connection,
    sql: &str,
    round_id: &str,
    wallet_id: &str,
) -> Result<Vec<ShareDelegationRecord>, VotingError> {
    let rows = query_map(
        conn,
        sql,
        named_params! { ":round_id": round_id, ":wallet_id": wallet_id },
        |row| {
            let urls_json: String = row.get(3)?;
            let nullifier_blob: Vec<u8> = row.get(4)?;
            let confirmed_int: i32 = row.get(5)?;
            let round_id_val: String = row.get(8)?;
            Ok((
                row.get::<_, u32>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, u32>(2)?,
                urls_json,
                nullifier_blob,
                confirmed_int != 0,
                row.get::<_, u64>(6)?,
                row.get::<_, u64>(7)?,
                round_id_val,
            ))
        },
    )
    .await
    .map_err(|e| VotingError::Internal {
        message: format!("failed to query share delegations: {}", e),
    })?;

    let mut results = Vec::new();
    for row in rows {
        let (
            bundle_index,
            proposal_id,
            share_index,
            urls_json,
            nullifier,
            confirmed,
            submit_at,
            created_at,
            round_id_val,
        ) = row;
        let sent_to_urls: Vec<String> =
            serde_json::from_str(&urls_json).map_err(|e| VotingError::Internal {
                message: format!("failed to deserialize sent_to_urls: {}", e),
            })?;
        results.push(ShareDelegationRecord {
            round_id: round_id_val,
            bundle_index,
            proposal_id,
            share_index,
            sent_to_urls,
            nullifier,
            confirmed,
            submit_at,
            created_at,
        });
    }
    Ok(results)
}

/// Mark a share delegation as confirmed on-chain.
pub async fn mark_share_confirmed(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
    proposal_id: u32,
    share_index: u32,
) -> Result<(), VotingError> {
    ensure_share_matches_ballot_intent(conn, round_id, wallet_id, bundle_index, proposal_id)
        .await?;
    let updated = conn
        .execute(
            "UPDATE voting_share_delegations SET confirmed = 1 \
             WHERE round_id = :round_id AND wallet_id = :wallet_id \
             AND bundle_index = :bundle_index AND proposal_id = :proposal_id AND share_index = :share_index",
            named_params! {
                ":round_id": round_id,
                ":wallet_id": wallet_id,
                ":bundle_index": bundle_index,
                ":proposal_id": proposal_id,
                ":share_index": share_index,
            },
        )
        .await
        .map_err(|e| VotingError::Internal {
            message: format!("failed to mark share confirmed: {}", e),
        })?;
    if updated == 0 {
        return Err(VotingError::Internal {
            message: format!(
                "no share delegation found: round={}, bundle={}, proposal={}, share={}",
                round_id, bundle_index, proposal_id, share_index
            ),
        });
    }
    Ok(())
}

async fn ensure_share_matches_ballot_intent(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
    proposal_id: u32,
) -> Result<(), VotingError> {
    let intent =
        load_ballot_intent(conn, round_id, wallet_id, proposal_id, "share delegation").await?;
    let Some((skipped, choice)) = intent else {
        return Ok(());
    };
    if skipped != 0 {
        return Err(VotingError::InvalidInput {
            message: format!(
                "cannot record share delegation for skipped proposal round={}, wallet={}, bundle={}, proposal={}",
                round_id, wallet_id, bundle_index, proposal_id
            ),
        });
    }
    let Some(choice) = choice else {
        return Err(VotingError::InvalidInput {
            message: format!(
                "ballot intent choice missing for round={}, wallet={}, proposal={}",
                round_id, wallet_id, proposal_id
            ),
        });
    };
    let vote_choice = load_vote_choice_for_intent_check(
        conn,
        round_id,
        wallet_id,
        bundle_index,
        proposal_id,
        "share delegation",
    )
    .await?;
    if vote_choice == Some(choice) {
        return Ok(());
    }
    Err(VotingError::InvalidInput {
        message: format!(
            "share delegation conflicts with ballot intent for round={}, wallet={}, bundle={}, proposal={}",
            round_id, wallet_id, bundle_index, proposal_id
        ),
    })
}

async fn ensure_vote_submission_matches_ballot_intent(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
    proposal_id: u32,
) -> Result<(), VotingError> {
    let intent =
        load_ballot_intent(conn, round_id, wallet_id, proposal_id, "vote submission").await?;
    let Some((skipped, choice)) = intent else {
        return Ok(());
    };
    let vote_choice = load_vote_choice_for_intent_check(
        conn,
        round_id,
        wallet_id,
        bundle_index,
        proposal_id,
        "vote submission",
    )
    .await?;
    let Some(vote_choice) = vote_choice else {
        return Ok(());
    };
    if skipped != 0 {
        return Err(VotingError::InvalidInput {
            message: format!(
                "cannot record vote submission for skipped proposal round={}, wallet={}, bundle={}, proposal={}",
                round_id, wallet_id, bundle_index, proposal_id
            ),
        });
    }
    let Some(choice) = choice else {
        return Err(VotingError::InvalidInput {
            message: format!(
                "ballot intent choice missing for round={}, wallet={}, proposal={}",
                round_id, wallet_id, proposal_id
            ),
        });
    };
    if vote_choice == choice {
        return Ok(());
    }
    Err(VotingError::InvalidInput {
        message: format!(
            "vote submission conflicts with ballot intent for round={}, wallet={}, bundle={}, proposal={}",
            round_id, wallet_id, bundle_index, proposal_id
        ),
    })
}

async fn load_ballot_intent(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    proposal_id: u32,
    artifact: &str,
) -> Result<Option<(i64, Option<i64>)>, VotingError> {
    conn.query_row(
        "SELECT skipped, choice FROM voting_ballot_intent
         WHERE round_id = :round_id
           AND wallet_id = :wallet_id
           AND proposal_id = :proposal_id",
        named_params! {
            ":round_id": round_id,
            ":wallet_id": wallet_id,
            ":proposal_id": proposal_id as i64,
        },
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .await
    .optional()
    .map_err(|e| VotingError::Internal {
        message: format!("failed to load ballot intent for {}: {}", artifact, e),
    })
}

async fn load_vote_choice_for_intent_check(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
    proposal_id: u32,
    artifact: &str,
) -> Result<Option<i64>, VotingError> {
    conn.query_row(
        "SELECT choice FROM voting_votes
         WHERE round_id = :round_id
           AND wallet_id = :wallet_id
           AND bundle_index = :bundle_index
           AND proposal_id = :proposal_id",
        named_params! {
            ":round_id": round_id,
            ":wallet_id": wallet_id,
            ":bundle_index": bundle_index as i64,
            ":proposal_id": proposal_id as i64,
        },
        |row| row.get(0),
    )
    .await
    .optional()
    .map_err(|e| VotingError::Internal {
        message: format!("failed to load vote choice for {}: {}", artifact, e),
    })
}

/// Append new server URLs to a share delegation's sent_to_urls.
/// Used after resubmitting an overdue share to additional servers.
pub async fn add_sent_servers(
    conn: &mut Connection,
    round_id: &str,
    wallet_id: &str,
    bundle_index: u32,
    proposal_id: u32,
    share_index: u32,
    new_urls: &[String],
) -> Result<(), VotingError> {
    ensure_share_matches_ballot_intent(conn, round_id, wallet_id, bundle_index, proposal_id)
        .await?;
    // Read current URLs
    let current_json: String = conn
        .query_row(
            "SELECT sent_to_urls FROM voting_share_delegations \
             WHERE round_id = :round_id AND wallet_id = :wallet_id \
             AND bundle_index = :bundle_index AND proposal_id = :proposal_id AND share_index = :share_index",
            named_params! {
                ":round_id": round_id,
                ":wallet_id": wallet_id,
                ":bundle_index": bundle_index,
                ":proposal_id": proposal_id,
                ":share_index": share_index,
            },
            |row| row.get(0),
        )
        .await
        .map_err(|e| VotingError::Internal {
            message: format!("failed to read sent_to_urls for update: {}", e),
        })?;

    let mut urls: Vec<String> =
        serde_json::from_str(&current_json).map_err(|e| VotingError::Internal {
            message: format!("failed to deserialize sent_to_urls: {}", e),
        })?;

    // Append new URLs (deduplicated)
    for url in new_urls {
        if !urls.contains(url) {
            urls.push(url.clone());
        }
    }

    let updated_json = serde_json::to_string(&urls).map_err(|e| VotingError::Internal {
        message: format!("failed to serialize updated sent_to_urls: {}", e),
    })?;

    conn.execute(
        "UPDATE voting_share_delegations SET sent_to_urls = :urls, submit_at = 0 \
         WHERE round_id = :round_id AND wallet_id = :wallet_id \
         AND bundle_index = :bundle_index AND proposal_id = :proposal_id AND share_index = :share_index",
        named_params! {
            ":urls": updated_json,
            ":round_id": round_id,
            ":wallet_id": wallet_id,
            ":bundle_index": bundle_index,
            ":proposal_id": proposal_id,
            ":share_index": share_index,
        },
    )
    .await
    .map_err(|e| VotingError::Internal {
        message: format!("failed to update sent_to_urls: {}", e),
    })?;
    Ok(())
}
