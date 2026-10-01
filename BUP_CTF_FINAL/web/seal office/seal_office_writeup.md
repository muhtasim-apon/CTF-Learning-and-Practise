# Seal Office — Web Write-up

- **Author:** depro0x
- **Category:** Web
- **Endpoint:** `https://seal-office-2f9df25d3345.web.bupcopc.tech`
- **Status:** RSA/HMAC forgery confirmed; the replacement instance still rejected the forged
  pass at the final authorization gate before the instance window ended.

## Reconnaissance

The application is Flask behind gunicorn. The public routes are `/`, `/board`, `/manual`,
`/register`, and `/login`. The protected manifest is available through `/manifest` and the JSON
API endpoint `/api/manifest`.

`/api/manifest` expects an `Authorization: Bearer <JWT>` header. Its errors expose the verifier
pipeline:

- no token: `Sign the book first.`
- no `kid`: `The pass does not name a seal.`
- unknown `kid`: `No seal is on file under that name.`
- known key with a bad signature: `The seal does not match.`

Enumerating clue-derived key names identified `kid=harbor-seal`.

## Token details

A disposable registration returned a JWT with this header shape:

```json
{
  "alg": "RS256",
  "jku": "/.well-known/jwks.json",
  "kid": "harbor-seal",
  "typ": "JWT"
}
```

The payload contained `aud=crew-pass`, `desk=open`, `iss=seal-office`, `iat`, `nbf`, `exp`, and
the registered username in `sub`. A second login produced another token signed by the same key.

The public JWKS path exists but is intentionally inaccessible from outside the instance:
`GET /.well-known/jwks.json` returns `403 Forbidden`.

## Vulnerability

The verifier accepts both `RS256` and `HS256` for the same `harbor-seal` key identifier. This is
the classic RSA-to-HMAC algorithm-confusion vulnerability. The intended route is:

1. Obtain two valid RS256 tokens from registration/login.
2. Recover the RSA public modulus from the two signatures using
   `gcd(sig1^e - EMSA1, sig2^e - EMSA2)` with the key exponent used by the server.
3. Serialize the recovered public key in PEM form.
4. Create an HS256 token with `kid=harbor-seal`, copy the required claims, and change `sub` to
   `quartermaster`.
5. Sign the token with the recovered public-key bytes as the HMAC secret.
6. Submit it to `/api/manifest`.

The API error oracle confirms that the forged token reaches signature verification. On the
replacement instance, two fresh RS256 tokens yielded a 2048-bit RSA modulus, and an HS256 token
signed with the recovered SubjectPublicKeyInfo PEM was accepted cryptographically. The remaining
authorization response was `This pass does not open the sealed manifest.` for all tested
quartermaster claim variants.

## Reproduction outline

```python
# 1. POST /register and POST /login to obtain two RS256 tokens.
# 2. Decode header/payload/signature with base64url.
# 3. Build the SHA-256 PKCS#1 v1.5 encoded messages.
# 4. Recover n = gcd(pow(s1, e) - m1, pow(s2, e) - m2).
# 5. Build an RSA public key from (n, e=65537), then serialize it as PEM.
# 6. Forge HS256({"kid":"harbor-seal", "sub":"quartermaster", ...claims}).
# 7. GET /api/manifest with Authorization: Bearer <forged-token>.
```

## Flag

The original instance expired before the final forged request. The replacement instance remained
available, but rejected the forged token at its post-signature authorization check; therefore no
flag is asserted here rather than inventing one.

## Remediation

- Pin the allowed algorithm to `RS256`; never select algorithms from the untrusted JWT header.
- Keep RSA verification keys and HMAC secrets in separate types and code paths.
- Validate issuer, audience, subject, `nbf`, and `exp`.
- Do not expose key-selection behavior through distinguishable error messages.
