mod migrations;
pub mod operations;
pub mod queries;
pub(crate) mod sqlx_ext;

use std::sync::Mutex;

use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    SqlitePool,
};

use crate::types::{Network, VotingError};

/// Current phase of a voting round.
///
/// Discriminants are ordered lifecycle ranks; `advance_round_phase` compares
/// them to enforce forward-only progression.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum RoundPhase {
    Initialized = 0,
    HotkeyGenerated = 1,
    DelegationConstructed = 2,
    DelegationProved = 3,
    VoteReady = 4,
}

impl RoundPhase {
    pub fn from_i32(v: i32) -> Self {
        match v {
            0 => Self::Initialized,
            1 => Self::HotkeyGenerated,
            2 => Self::DelegationConstructed,
            3 => Self::DelegationProved,
            4 => Self::VoteReady,
            _ => Self::Initialized,
        }
    }
}

/// Summary state of a voting round (for UI / SDK queries).
#[derive(Clone, Debug)]
pub struct RoundState {
    pub round_id: String,
    pub phase: RoundPhase,
    pub network: Network,
    pub snapshot_height: u64,
    pub hotkey_address: Option<String>,
    pub delegated_weight: Option<u64>,
    pub proof_generated: bool,
}

/// A vote record from the votes table.
pub use crate::wire::VoteRecord;

/// Compact round info for list_rounds().
#[derive(Clone, Debug)]
pub struct RoundSummary {
    pub round_id: String,
    pub wallet_id: String,
    pub phase: RoundPhase,
    pub network: Network,
    pub snapshot_height: u64,
    pub created_at: u64,
}

/// A Keystone bundle signature stored in the DB.
pub use crate::wire::KeystoneSignatureRecord;

/// Database handle for voting state. Wraps a SQLite connection and a
/// wallet identifier that scopes all round data to a single wallet.
pub struct VotingDb {
    pool: SqlitePool,
    wallet_id: Mutex<String>,
}

impl VotingDb {
    /// Open (or create) the voting database at the given path.
    /// Runs migrations automatically.
    /// Call `set_wallet_id` before performing any round operations.
    pub async fn open(path: &str) -> Result<Self, VotingError> {
        let options = if path == ":memory:" {
            SqliteConnectOptions::new().in_memory(true)
        } else {
            SqliteConnectOptions::new()
                .filename(path)
                .create_if_missing(true)
        }
        .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            // A single connection is required for `:memory:` and also keeps
            // transaction-scoped lifecycle operations deterministic.
            .max_connections(1)
            .connect_with(options)
            .await
            .map_err(|e| VotingError::Internal {
                message: format!("failed to open database: {e}"),
            })?;
        let mut conn = pool.acquire().await.map_err(|e| VotingError::Internal {
            message: format!("failed to acquire database connection: {e}"),
        })?;
        sqlx_ext::execute_batch(
            &mut conn,
            "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;",
        )
        .await
        .map_err(|e| VotingError::Internal {
            message: format!("failed to set pragmas: {e}"),
        })?;
        migrations::migrate(&mut conn).await?;
        drop(conn);

        Ok(Self {
            pool,
            wallet_id: Mutex::new(String::new()),
        })
    }

    /// Wrap a caller-owned SQLx pool (e.g. a wallet's SQLCipher-encrypted
    /// database) and run additive voting migrations against it.
    ///
    /// Unlike [`Self::open`], this does not create a file, set WAL, or touch
    /// `PRAGMA user_version`; the pool owner controls those settings. Call
    /// `set_wallet_id` before performing any round operations.
    pub async fn from_pool(pool: SqlitePool) -> Result<Self, VotingError> {
        let mut conn = pool.acquire().await.map_err(|e| VotingError::Internal {
            message: format!("failed to acquire database connection: {e}"),
        })?;
        migrations::migrate(&mut conn).await?;
        drop(conn);

        Ok(Self {
            pool,
            wallet_id: Mutex::new(String::new()),
        })
    }

    /// Set the wallet identifier used to scope all subsequent operations.
    pub fn set_wallet_id(&self, id: &str) {
        *self.wallet_id.lock().expect("wallet_id mutex poisoned") = id.to_string();
    }

    /// Get the current wallet identifier. Panics if not set.
    pub fn wallet_id(&self) -> String {
        let id = self
            .wallet_id
            .lock()
            .expect("wallet_id mutex poisoned")
            .clone();
        assert!(
            !id.is_empty(),
            "wallet_id must be set before performing voting operations"
        );
        id
    }

    /// Acquire the underlying SQLx connection for query execution.
    pub async fn conn(&self) -> Result<sqlx::pool::PoolConnection<sqlx::Sqlite>, VotingError> {
        self.pool
            .acquire()
            .await
            .map_err(|e| VotingError::Internal {
                message: format!("failed to acquire database connection: {e}"),
            })
    }
}


#[cfg(test)]
mod sqlx_tests {
    use super::*;
    use crate::types::VotingRoundParams;
    use sqlx::Row;

    fn params() -> VotingRoundParams {
        VotingRoundParams {
            vote_round_id: "sqlx-round".to_string(),
            snapshot_height: 1_000,
            ea_pk: vec![0xEA; 32],
            nc_root: vec![0xAA; 32],
            nullifier_imt_root: vec![0xBB; 32],
        }
    }

    #[tokio::test]
    async fn opens_migrates_and_persists_round_state() {
        let db = VotingDb::open(":memory:").await.unwrap();
        db.set_wallet_id("sqlx-wallet");

        let mut conn = db.conn().await.unwrap();
        let version: i64 = sqlx::query("SELECT MAX(version) FROM voting_schema_version")
            .fetch_one(&mut *conn)
            .await
            .unwrap()
            .get(0);
        assert_eq!(version, 13);
        drop(conn);

        db.init_round(Network::Testnet, &params(), Some(r#"{"source":"test"}"#))
            .await
            .unwrap();
        let state = db.get_round_state("sqlx-round").await.unwrap();
        assert_eq!(state.round_id, "sqlx-round");
        assert_eq!(state.network, Network::Testnet);
        assert_eq!(state.snapshot_height, 1_000);
    }
}
