mod body;
mod client_metadata;
mod config;
mod csrf;
mod db;
mod error;
mod html;
mod idgen;
mod pkce;
mod routes;
mod session;
mod state;
mod util;
mod webauthn;

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, UnixListener};

use crate::client_metadata::build_https_client;
use crate::config::{BindAddr, Config};
use crate::db::Db;
use crate::state::AppState;
use crate::webauthn::WebauthnState;

const SESSION_CLEANUP_INTERVAL: Duration = Duration::from_secs(300);

trait Conn: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Conn for T {}

/// Wraps either listener type so the accept loop below doesn't need to be
/// written out twice. A unix socket is used for the same-host daemontools
/// deployment; TCP is needed when the reverse proxy runs on a different
/// host (e.g. proxying over a LAN to this box).
enum Listener {
    Unix(UnixListener),
    Tcp(TcpListener),
}

impl Listener {
    async fn bind(addr: &BindAddr) -> Listener {
        match addr {
            BindAddr::Unix(path) => {
                // Remove a stale socket file from a previous run -- bind
                // fails otherwise. Safe: daemontools guarantees only one
                // instance of this service runs at a time.
                let _ = std::fs::remove_file(path);
                let listener = UnixListener::bind(path).expect("failed to bind unix socket");
                tracing::info!(socket = %path, "listening");
                Listener::Unix(listener)
            }
            BindAddr::Tcp(addr) => {
                let listener = TcpListener::bind(addr).await.expect("failed to bind tcp socket");
                tracing::info!(%addr, "listening");
                Listener::Tcp(listener)
            }
        }
    }

    async fn accept(&self) -> std::io::Result<Box<dyn Conn>> {
        match self {
            Listener::Unix(l) => l.accept().await.map(|(s, _)| Box::new(s) as Box<dyn Conn>),
            Listener::Tcp(l) => l.accept().await.map(|(s, _)| Box::new(s) as Box<dyn Conn>),
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = Config::from_env();
    let db = Db::open(&config.database_path);
    let webauthn = WebauthnState::new(&config.rp_id, &config.rp_origin);
    let https_client = build_https_client();

    let bind_addr_for_cleanup = match &config.bind_addr {
        BindAddr::Unix(path) => Some(path.clone()),
        BindAddr::Tcp(_) => None,
    };
    let listener = Listener::bind(&config.bind_addr).await;

    let state = Arc::new(AppState {
        db,
        webauthn,
        https_client,
        config,
    });

    spawn_session_cleanup(state.clone());

    let mut shutdown = shutdown_signal();

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok(stream) = accepted else { continue };
                let state = state.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let service = service_fn(move |req| {
                        let state = state.clone();
                        async move {
                            let method = req.method().clone();
                            let uri = req.uri().clone();
                            // Log only a short prefix -- enough to correlate which
                            // session a request used across log lines without
                            // writing the full session secret to disk.
                            let owner_cookie_prefix = crate::session::get_cookie(req.headers(), crate::session::OWNER_COOKIE)
                                .map(|c| c.chars().take(8).collect::<String>());
                            let resp = routes::dispatch(req, &state).await;
                            tracing::info!(%method, %uri, ?owner_cookie_prefix, status = %resp.status(), "request");
                            Ok::<_, Infallible>(resp)
                        }
                    });
                    if let Err(err) = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .await
                    {
                        tracing::debug!(%err, "connection error");
                    }
                });
            }
            _ = &mut shutdown => {
                tracing::info!("shutting down");
                break;
            }
        }
    }

    if let Some(path) = bind_addr_for_cleanup {
        let _ = std::fs::remove_file(path);
    }
}

fn spawn_session_cleanup(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(SESSION_CLEANUP_INTERVAL);
        loop {
            interval.tick().await;
            let _ = state.db.call(crate::db::cleanup_expired_sessions).await;
        }
    });
}

fn shutdown_signal() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
    Box::pin(async {
        let ctrl_c = tokio::signal::ctrl_c();
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {},
            _ = term.recv() => {},
        }
    })
}
