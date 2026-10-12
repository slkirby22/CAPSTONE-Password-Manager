# Web-first vault interface

The legacy vault API is retired. Use the web interface to list, reveal, create,
update, and delete vault items. This version does not support the historical
mobile client and introduces no API reveal endpoint or replacement v1 vault API.

The following historical routes retain authentication but return HTTP 410 Gone
for a valid JWT tied to a current account:

- `GET /api/dashboard`
- `POST /api/passwords`
- `PATCH /api/passwords/<selector>`
- `DELETE /api/passwords/<selector>`

The response body is:

```json
{
  "error": "vault_api_retired",
  "message": "Vault API retired. Use the web interface; this version does not support the historical mobile client."
}
```

These routes do not decrypt secrets, return vault metadata, resolve an item,
parse a mutation payload, or mutate vault records. Their JSON mutation routes
remain CSRF-exempt because authentication is bearer-header-only; a web session
cookie never authorizes an API request.

`POST /api/login` and `POST /api/logout` remain available for their existing
credential-verification and token-revocation contracts. Missing, invalid,
expired, revoked, legacy, stale, and deleted-account JWTs fail authentication
before retirement is reported. Tokens cannot transfer to a replacement account
when a numeric account ID is reused. Clients should migrate to the web interface,
not retry retired vault operations or expect login to restore mobile vault access.
