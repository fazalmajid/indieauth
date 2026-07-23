mod codes;
mod credentials;
mod sessions;
mod tokens;

pub use codes::*;
pub use credentials::*;
pub use sessions::*;
pub use tokens::*;

use rusqlite::Connection;
use tokio::sync::{mpsc, oneshot};

type Job = Box<dyn FnOnce(&Connection) + Send>;

/// A handle to the single SQLite writer thread. SQLite has no meaningful
/// concurrent-write story worth fighting; instead of an async driver we
/// dedicate one OS thread to the one `Connection` and funnel every query
/// through it as a boxed closure, replied to via a oneshot channel. This
/// keeps the whole DB layer on plain rusqlite (sync, minimal deps) while
/// still composing with async handlers.
#[derive(Clone)]
pub struct Db {
    tx: mpsc::UnboundedSender<Job>,
}

impl Db {
    pub fn open(path: &str) -> Db {
        let (tx, mut rx) = mpsc::unbounded_channel::<Job>();
        let path = path.to_string();
        std::thread::Builder::new()
            .name("sqlite-writer".into())
            .spawn(move || {
                let conn = Connection::open(&path).expect("failed to open sqlite database");
                conn.execute_batch(
                    "PRAGMA journal_mode = WAL;
                     PRAGMA busy_timeout = 5000;
                     PRAGMA foreign_keys = ON;",
                )
                .expect("failed to configure sqlite connection");
                run_migrations(&conn).expect("failed to run migrations");
                while let Some(job) = rx.blocking_recv() {
                    job(&conn);
                }
            })
            .expect("failed to spawn sqlite writer thread");
        Db { tx }
    }

    /// Run a closure against the connection on the writer thread, awaiting
    /// its result from the calling async context.
    pub async fn call<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&Connection) -> T + Send + 'static,
        T: Send + 'static,
    {
        let (reply_tx, reply_rx) = oneshot::channel();
        let job: Job = Box::new(move |conn| {
            let result = f(conn);
            // Ignore send errors: the caller may have dropped the future
            // (e.g. on request cancellation), which is not our problem.
            let _ = reply_tx.send(result);
        });
        self.tx
            .send(job)
            .expect("sqlite writer thread has shut down");
        reply_rx.await.expect("sqlite writer thread dropped reply")
    }
}

/// Hand-rolled migration runner: no `sqlx`, so we track schema version with
/// SQLite's own `PRAGMA user_version` and apply any `migrations/NNNN_*.sql`
/// files numbered above it, in order, each in its own transaction.
fn run_migrations(conn: &Connection) -> rusqlite::Result<()> {
    const MIGRATIONS: &[(i64, &str)] = &[(1, include_str!("../../migrations/0001_init.sql"))];

    let current: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    for (version, sql) in MIGRATIONS {
        if *version > current {
            conn.execute_batch(sql)?;
            conn.execute_batch(&format!("PRAGMA user_version = {version}"))?;
        }
    }
    Ok(())
}
