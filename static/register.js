document.getElementById('start').addEventListener('click', () => {
  const label = document.getElementById('label').value.trim();
  setStatus('Waiting for your passkey...');

  const options = readCeremonyOptions();
  options.challenge = b64urlToBuf(options.challenge);
  options.user.id = b64urlToBuf(options.user.id);
  if (options.excludeCredentials) {
    for (const c of options.excludeCredentials) c.id = b64urlToBuf(c.id);
  }

  navigator.credentials.create({ publicKey: options })
    .then((cred) => {
      const body = {
        id: cred.id,
        rawId: bufToB64url(cred.rawId),
        type: cred.type,
        response: {
          attestationObject: bufToB64url(cred.response.attestationObject),
          clientDataJSON: bufToB64url(cred.response.clientDataJSON),
        },
        label: label.length > 0 ? label : null,
      };
      return fetch('/auth/register/finish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
    })
    .then((resp) => {
      if (resp.redirected) { window.location = resp.url; return; }
      if (resp.ok) { setStatus('Passkey registered.'); }
      else { resp.text().then((t) => setStatus('Registration failed: ' + t)); }
    })
    .catch((err) => setStatus('Registration failed: ' + err));
});
