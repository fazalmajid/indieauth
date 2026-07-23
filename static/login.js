const options = readCeremonyOptions();
options.challenge = b64urlToBuf(options.challenge);
if (options.allowCredentials) {
  for (const c of options.allowCredentials) c.id = b64urlToBuf(c.id);
}

navigator.credentials.get({ publicKey: options })
  .then((cred) => {
    const body = {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      response: {
        authenticatorData: bufToB64url(cred.response.authenticatorData),
        clientDataJSON: bufToB64url(cred.response.clientDataJSON),
        signature: bufToB64url(cred.response.signature),
        userHandle: cred.response.userHandle ? bufToB64url(cred.response.userHandle) : null,
      },
    };
    return fetch('/auth/login/finish', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  })
  .then((resp) => {
    if (resp.redirected) { window.location = resp.url; return; }
    if (resp.ok) { window.location.reload(); }
    else { resp.text().then((t) => setStatus('Sign-in failed: ' + t)); }
  })
  .catch((err) => setStatus('Sign-in failed: ' + err));
