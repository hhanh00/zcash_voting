use sqlx::{Acquire, SqliteConnection};

use crate::storage::sqlx_ext::{execute_batch, query_row, Params};
use crate::VotingError;

/// Current voting schema version, tracked in the `voting_schema_version`
/// table rather than `PRAGMA user_version` so the voting schema can share a
/// database with a host wallet without claiming its version pragma.
const CURRENT_VERSION: u32 = 13;

const INIT_SQL: &str = include_str!("migrations/001_init.sql");

/// Applies the voting schema additively to the given connection.
///
/// The voting schema is namespaced (`voting_*` tables) and is intended to be
/// embedded in a host wallet database (e.g. zkool's SQLCipher wallet DB). All
/// statements are idempotent and nothing is ever dropped. Old standalone
/// voting databases with unprefixed tables are deliberately not migrated
/// (pre-launch).
pub async fn migrate(conn: &mut SqliteConnection) -> Result<(), VotingError> {
    execute_batch(
        conn,
        "CREATE TABLE IF NOT EXISTS voting_schema_version (version INTEGER NOT NULL);",
    )
    .await
    .map_err(|e| VotingError::Internal {
        message: format!("failed to create voting schema version table: {e}"),
    })?;

    let version: Option<i64> = query_row(
        conn,
        "SELECT MAX(version) FROM voting_schema_version",
        Params::default(),
        |row| row.get(0),
    )
    .await
    .map_err(|e| VotingError::Internal {
        message: format!("failed to read voting schema version: {e}"),
    })?;

    match version {
        None => {
            let mut tx = conn.begin().await.map_err(|e| VotingError::Internal {
                message: format!("failed to start database migration transaction: {e}"),
            })?;
            execute_batch(&mut tx, INIT_SQL)
                .await
                .map_err(|e| VotingError::Internal {
                    message: format!("failed to create voting schema: {e}"),
                })?;
            execute_batch(
                &mut tx,
                &format!("INSERT INTO voting_schema_version (version) VALUES ({CURRENT_VERSION})"),
            )
            .await
            .map_err(|e| VotingError::Internal {
                message: format!("failed to record voting schema version: {e}"),
            })?;
            tx.commit().await.map_err(|e| VotingError::Internal {
                message: format!("failed to commit database migration: {e}"),
            })?;
        }
        Some(v) if v as u32 > CURRENT_VERSION => {
            return Err(VotingError::Internal {
                message: format!(
                    "unsupported newer voting schema version: expected at most {}, got {}",
                    CURRENT_VERSION, v
                ),
            });
        }
        Some(v) if (v as u32) < CURRENT_VERSION => {
            // Future additive migrations re-run the idempotent schema batch.
            let mut tx = conn.begin().await.map_err(|e| VotingError::Internal {
                message: format!("failed to start database migration transaction: {e}"),
            })?;
            execute_batch(&mut tx, INIT_SQL)
                .await
                .map_err(|e| VotingError::Internal {
                    message: format!("failed to upgrade voting schema: {e}"),
                })?;
            execute_batch(
                &mut tx,
                &format!("UPDATE voting_schema_version SET version = {CURRENT_VERSION}"),
            )
            .await
            .map_err(|e| VotingError::Internal {
                message: format!("failed to update voting schema version: {e}"),
            })?;
            tx.commit().await.map_err(|e| VotingError::Internal {
                message: format!("failed to commit database migration: {e}"),
            })?;
        }
        _ => {}
    }

    Ok(())
}
