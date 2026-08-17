//! Probes the stage PIR server under the app's exact layering: sqlx pool on
//! one runtime, DB query + PIR connect + fetch on a big-stack thread with a
//! fresh runtime.
//!
//! Run: cargo run -p zcash_voting --example pir_probe
use std::sync::Arc;
use std::time::Instant;

use pasta_curves::pallas;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use zcash_voting::config::PirLayout;
use zcash_voting::pir::PirProofSource;
use zcash_voting::storage::VotingDb;
use zcash_voting::{connect_pir, HyperTransport};

const LAYOUT: PirLayout = PirLayout {
    pir_depth: 19,
    tier0_layers: 12,
    tier1_layers: 7,
    poly_len: 4096,
};
const URL: &str = "https://stage.pir.valargroup.org";

fn main() {
    // Config 1: everything on one runtime (baseline).
    {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let t = Instant::now();
        rt.block_on(async {
            let client = connect_pir(LAYOUT, URL, Arc::new(HyperTransport::new()))
                .await
                .expect("connect");
            client
                .fetch_proofs(&[pallas::Base::from(7u64)])
                .await
                .expect("fetch");
        });
        println!("[single-runtime] connect+fetch {:.2}s", t.elapsed().as_secs_f64());
    }

    // Config 3 (app shape): pool created on rt_a, then a 512MB-stack thread
    // with a fresh runtime does a sqlx query + PIR connect + fetch.
    let rt_a = tokio::runtime::Runtime::new().unwrap();
    let db: VotingDb = rt_a.block_on(async {
        let db_path = "/tmp/pir_probe.db";
        let _ = std::fs::remove_file(db_path);
        let opts = SqliteConnectOptions::new().filename(db_path).create_if_missing(true);
        let pool = SqlitePoolOptions::new().max_connections(5).connect_with(opts).await.unwrap();
        let db = VotingDb::from_pool(pool).await.unwrap();
        db.set_wallet_id("probe-wallet");
        db
    });
    println!("[app-shape] pool created on rt_a");

    let t = Instant::now();
    let handle = std::thread::Builder::new()
        .stack_size(512 * 1024 * 1024)
        .name("probe-thread".to_string())
        .spawn(move || {
            let rt_b = tokio::runtime::Runtime::new().unwrap();
            rt_b.block_on(async {
                // sqlx query on the pool created elsewhere (the app does
                // load_round_params etc. here before the PIR phase).
                let mut conn = db.conn().await.expect("acquire");
                let v: i64 = sqlx::query_scalar("SELECT 1").fetch_one(&mut *conn).await.expect("query");
                assert_eq!(v, 1);
                drop(conn);
                println!("  sqlx query on thread runtime ok ({:.2}s)", t.elapsed().as_secs_f64());

                let client = connect_pir(LAYOUT, URL, Arc::new(HyperTransport::new()))
                    .await
                    .expect("connect on thread runtime");
                client
                    .fetch_proofs(&[pallas::Base::from(7u64)])
                    .await
                    .expect("fetch on thread runtime");
            });
        })
        .unwrap();
    handle.join().unwrap();
    println!("[app-shape] sqlx + PIR connect+fetch on thread runtime {:.2}s", t.elapsed().as_secs_f64());
}
