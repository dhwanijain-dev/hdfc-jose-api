# CorpPay JOSE utility API

This service provides two operations for the SAP client's CorpPay JOSE-High integration:

- `POST /encrypt`: sign a JSON request as JWS with the partner private key, then encrypt the JWS as compact JWE with HDFC's JOSE public key.
- `POST /decrypt`: decrypt HDFC's compact JWE response with the partner private key, then verify its JWS signature with HDFC's JOSE public key and return the JSON payload.

Project guides:

- [PRD](PRD.md): scope, contract, security, acceptance criteria, and open integration inputs.
- [Client workflow](CLIENT_WORKFLOW.md): onboarding inputs and the SAP-to-HDFC payment/inquiry lifecycle.
- [Testing guide](TESTING.md): local route smoke test and HDFC UAT sequence.

It does not call HDFC payment or inquiry endpoints and does not obtain OAuth tokens. The SAP application remains responsible for the API-specific payment payload, headers, OAuth, transaction identifiers, and HDFC network call.

## Configuration

For a local Windows/UAT setup, copy `.env.example` to `.env` and set the paths and secrets. The app loads `.env` automatically from the working directory through `python-dotenv`; environment variables already set by the server override file values. Keep the completed `.env` local to the deployment and out of source control.

Set these values:

- `PARTNER_PRIVATE_KEY_PATH`: RSA PEM private key used for partner signing and response decryption.
- `HDFC_PUBLIC_KEY_PATH`: RSA public key/certificate explicitly issued for the CorpPay JOSE integration.
- `PARTNER_PUBLIC_CERT_PATH`: optional matching partner public certificate (PEM, DER, or PKCS#7). If omitted, the public key is derived from the private key.
- `PARTNER_PRIVATE_KEY_PASSWORD`: optional password for an encrypted PEM key.
- `MAX_REQUEST_BYTES`: optional request-size limit; defaults to 1 MiB.

The TLS endpoint certificate files in `newfiles/` are not automatically treated as the CorpPay JOSE encryption key. Confirm the correct JOSE key and KID with HDFC's onboarding materials before deployment.

## Run locally

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

On Windows PowerShell, activate with `.venv\Scripts\Activate.ps1` and start with `py -m uvicorn app.main:app --host 127.0.0.1 --port 8000` from the project folder.

Use HTTPS and preferably mutual TLS between the SAP system and this service in deployment. Keep private keys and API credentials outside the repository; never log payloads, compact JOSE values, authorization headers, or key material.

## HTTP interface

`POST /encrypt` accepts the bank API JSON payload directly and returns:

```json
{"jose":"<compact JWE>","content_type":"application/jose"}
```

`POST /decrypt` accepts:

```json
{"jose":"<compact JWE response>"}
```

and returns the verified bank response payload as JSON under `payload`.

The implementation follows the supplied JOSE spec's RS256 JWS, RSA-OAEP-256 JWE key management, A256GCM content encryption, and KID formula based on Base64URL(SHA-256(DER SubjectPublicKeyInfo)). Confirm exact header and serialization expectations against HDFC UAT before production use.
