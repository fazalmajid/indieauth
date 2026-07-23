//! Hand-written HTML page builders. There are only a handful of pages, so a
//! templating crate (askama et al) buys nothing here -- `escape` is the one
//! thing that matters, and it must be applied to every attacker-influenceable
//! value (client name/URL sourced from the client_id document) rendered on
//! the consent page.

pub fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// No inline `<style>` -- a `Content-Security-Policy` with no explicit
/// `style-src` falls back to `default-src` for styles too, and blocks
/// inline style the exact same way it blocks inline script (see
/// `ceremony_scripts`'s doc comment). An external, same-origin stylesheet
/// is allowed by a plain `'self'`.
fn page(title: &str, body: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<link rel="stylesheet" href="/auth/static/style.css">
</head>
<body>
{body}
</body>
</html>"#
    )
}

/// Renders the ceremony data as an inert JSON data island plus external
/// same-origin `<script>` tags -- deliberately *not* inline executable
/// script. Sites that set a `Content-Security-Policy` with a `script-src`/
/// `default-src` lacking `'unsafe-inline'` (a reasonable, common hardening
/// choice) silently drop inline scripts entirely. A
/// `type="application/json"` block isn't executable and so isn't governed
/// by script-src at all, and external same-origin scripts are allowed by
/// a plain `'self'`.
fn ceremony_scripts(options_json: &str, ceremony_script: &str) -> String {
    format!(
        r#"<script type="application/json" id="ceremony-options">{options_json}</script>
<script src="/auth/static/webauthn-common.js"></script>
<script src="{ceremony_script}"></script>"#
    )
}

/// `creation_options_json` is the `CreationChallengeResponse.publicKey`
/// object, verbatim from webauthn-rs -- safe to embed directly since it
/// originates entirely on our own server, never from user input.
///
/// Unlike login, registration waits for a button click before starting the
/// ceremony: the label input needs to be filled in first, and the
/// browser's native passkey dialog is modal, so there's no chance to type
/// a label once it's up.
pub fn register_page(creation_options_json: &str) -> String {
    let scripts = ceremony_scripts(creation_options_json, "/auth/static/register.js");
    let body = format!(
        r#"<h1>Register a passkey</h1>
<p>Give this passkey a label so you can tell it apart later (e.g. "YubiKey 5", "iPhone").</p>
<p><input type="text" id="label" placeholder="e.g. YubiKey 5" autofocus></p>
<p><button id="start">Register passkey</button></p>
<p id="status"></p>
{scripts}"#
    );
    page("Register a passkey", &body)
}

/// `request_options_json` is the `RequestChallengeResponse.publicKey`
/// object, verbatim from webauthn-rs.
pub fn login_page(request_options_json: &str) -> String {
    let scripts = ceremony_scripts(request_options_json, "/auth/static/login.js");
    let body = format!(
        r#"<h1>Sign in with your passkey</h1>
<p id="status">Waiting for your passkey...</p>
{scripts}"#
    );
    page("Sign in", &body)
}

pub struct ConsentClient<'a> {
    pub client_id: &'a str,
    pub client_name: Option<&'a str>,
    pub redirect_uri: &'a str,
    pub scopes: &'a [&'a str],
    pub me: &'a str,
}

pub fn consent_page(c: &ConsentClient) -> String {
    let name = c.client_name.unwrap_or(c.client_id);
    let scope_list = if c.scopes.is_empty() {
        "<li><em>No specific permissions (identity only)</em></li>".to_string()
    } else {
        c.scopes
            .iter()
            .map(|s| format!("<li>{}</li>", escape(s)))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let body = format!(
        r#"<h1>Sign in to {name}?</h1>
<div class="client">
  <p><strong>{name}</strong></p>
  <p><code>{client_id}</code></p>
  <p>Redirecting to: <code>{redirect_uri}</code></p>
</div>
<p>This will share your identity (<code>{me}</code>) and grant:</p>
<ul>{scope_list}</ul>
<form method="post" class="actions">
  <button type="submit" name="decision" value="approve">Approve</button>
  <button type="submit" name="decision" value="deny" class="deny">Deny</button>
</form>"#,
        name = escape(name),
        client_id = escape(c.client_id),
        redirect_uri = escape(c.redirect_uri),
        me = escape(c.me),
    );
    page("Sign in?", &body)
}

pub struct CredentialSummary<'a> {
    pub id_b64: &'a str,
    pub label: Option<&'a str>,
    pub created_at: &'a str,
    pub last_used_at: Option<&'a str>,
}

pub fn credentials_page(creds: &[CredentialSummary]) -> String {
    let rows = creds
        .iter()
        .map(|c| {
            format!(
                r#"<li>
  <strong>{label}</strong> -- registered {created}, last used {last_used}
  <form method="post" action="/auth/credentials/rename" class="inline-form">
    <input type="hidden" name="credential_id" value="{id}">
    <input type="text" name="label" value="{label_attr}" placeholder="e.g. YubiKey 5">
    <button type="submit">Rename</button>
  </form>
  <form method="post" action="/auth/credentials/delete" class="inline-form">
    <input type="hidden" name="credential_id" value="{id}">
    <button type="submit" {disabled}>Remove</button>
  </form>
</li>"#,
                label = escape(c.label.unwrap_or("(unlabeled passkey)")),
                label_attr = escape(c.label.unwrap_or("")),
                created = escape(c.created_at),
                last_used = escape(c.last_used_at.unwrap_or("never")),
                id = escape(c.id_b64),
                disabled = if creds.len() <= 1 { "disabled title=\"Can't remove your last passkey\"" } else { "" },
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let body = format!(
        r#"<h1>Your passkeys</h1>
<ul>{rows}</ul>
<p><a href="/auth/register">Register another passkey</a></p>
<form method="post" action="/auth/logout"><button type="submit">Sign out</button></form>"#
    );
    page("Your passkeys", &body)
}

pub fn error_page(message: &str) -> String {
    page("Error", &format!("<h1>Error</h1><p>{}</p>", escape(message)))
}

/// Navigates to `url` via JavaScript rather than an HTTP redirect. This
/// exists specifically for the consent form's approve/deny response: a
/// site with a `Content-Security-Policy` restricting `form-action` to a
/// same-origin allowlist (a reasonable, common hardening choice) has
/// browsers enforce that policy on the *entire* redirect chain resulting
/// from a form submission -- so an HTTP 3xx straight to an arbitrary
/// third-party `redirect_uri` (which IndieAuth requires, since any client
/// can be the destination) gets silently blocked, with no visible error,
/// just a stuck page. A same-origin 200 response satisfies `form-action`
/// on its own, and the actual cross-origin navigation happens afterward
/// via script, which
/// `form-action` doesn't govern at all.
pub fn redirect_page(url: &str) -> String {
    let url_json = serde_json::to_string(url).expect("url always serializes");
    let body = format!(
        r#"<p>Redirecting...</p>
<script type="application/json" id="redirect-url">{url_json}</script>
<script src="/auth/static/redirect.js"></script>"#
    );
    page("Redirecting...", &body)
}
