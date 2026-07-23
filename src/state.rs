use crate::client_metadata::HttpsClient;
use crate::config::Config;
use crate::db::Db;
use crate::webauthn::WebauthnState;

pub struct AppState {
    pub db: Db,
    pub webauthn: WebauthnState,
    pub https_client: HttpsClient,
    pub config: Config,
}
