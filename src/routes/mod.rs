mod authorize;
mod credentials;
mod introspection;
mod login;
mod metadata;
mod revocation;
mod token;

use http::{Method, Request};
use hyper::body::Incoming;

use crate::error::{Resp, javascript, not_found};
use crate::state::AppState;

pub async fn dispatch(req: Request<Incoming>, state: &AppState) -> Resp {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    match (method, path.as_str()) {
        (Method::GET, "/.well-known/oauth-authorization-server") => metadata::get(state),
        (Method::GET, "/auth/static/webauthn-common.js") => {
            javascript(include_str!("../../static/webauthn-common.js"))
        }
        (Method::GET, "/auth/static/register.js") => javascript(include_str!("../../static/register.js")),
        (Method::GET, "/auth/static/login.js") => javascript(include_str!("../../static/login.js")),
        (Method::GET, "/auth/static/redirect.js") => javascript(include_str!("../../static/redirect.js")),
        (Method::GET, "/auth/register") => login::register_page_handler(req, state).await,
        (Method::POST, "/auth/register/finish") => login::register_finish(req, state).await,
        (Method::GET, "/auth/login") => login::login_page_handler(req, state).await,
        (Method::POST, "/auth/login/finish") => login::login_finish(req, state).await,
        (Method::POST, "/auth/logout") => login::logout(req, state).await,
        (Method::GET, "/auth/credentials") => credentials::page(req, state).await,
        (Method::POST, "/auth/credentials/delete") => credentials::delete(req, state).await,
        (Method::POST, "/auth/credentials/rename") => credentials::rename(req, state).await,
        (Method::GET, "/auth/authorize") => authorize::get(req, state).await,
        (Method::POST, "/auth/authorize") => authorize::post(req, state).await,
        (Method::POST, "/auth/token") => token::post(req, state).await,
        (Method::POST, "/auth/introspection") => introspection::post(req, state).await,
        (Method::POST, "/auth/revocation") => revocation::post(req, state).await,
        _ => not_found(),
    }
}
