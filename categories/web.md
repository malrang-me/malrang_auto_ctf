# WEB — Web Security

## Tools
- **Chrome MCP**: navigate, read_page, find, form_input, JS exec
- **py-repl**: requests, JWT manipulation | **jq** for JSON filtering:
  ```bash
  wsl curl -s http://target/api | jq '.flag'
  wsl curl -s http://target/api | jq 'keys'
  ```
  **Rule**: JSON API → always `jq` filter. Never raw JSON in context.
- WSL: curl, sqlmap, python3 with requests

## Mandatory First Steps
1. Map all routes (source or spider)
2. Identify auth mechanism
3. Baseline request/response per endpoint
4. Source disclosure check (robots.txt, .git, backups)
5. Server tech fingerprint

## Attack Patterns

### Injection
- SQLi → UNION, blind boolean/time, error-based, stacked
- NoSQL → `{"$gt":""}`, `{"$regex":".*"}`
- SSTI → `{{7*7}}` then Jinja2/Twig payload
- CMDi → `; id`, `$(id)`, newline injection
- XPath/LDAP injection

### Auth
- JWT → none alg, weak secret, kid injection
- Session → predictable tokens, fixation, deser
- IDOR → increment IDs, parameter tampering
- Privilege escalation → role param, admin cookie

### File Ops
- Path traversal → `../../../etc/passwd`, null byte, double encoding
- Upload → extension bypass, content-type spoof, polyglot
- LFI/RFI → `php://filter`, `data://`, log poisoning
- SSRF → internal services, cloud metadata 169.254.169.254

### Client-Side
- XSS → reflected, stored, DOM; CSP bypass
- Prototype pollution → `__proto__` in JSON (Node.js)

### Deserialization
- Python pickle (`__reduce__`), PHP unserialize, Java ysoserial, Node node-serialize

### Parser Differentials
- HTTP smuggling (CL.TE, TE.CL), URL parser confusion, Unicode normalization

## Framework Priority
| Framework | Check First |
|---|---|
| Flask/Jinja2 | SSTI > debug > pickle |
| Express/Node | proto pollution > SSTI > SSRF |
| PHP | type juggling > LFI > deser |
| Django | ORM injection > SSTI > debug |

## Pitfalls
- Fresh session for testing (incognito)
- URL-encode properly, double if WAF
- Check rate limiting before brute
- SQLi: identify DB type first (MySQL vs PG vs SQLite)

## Advanced (L4+ only)
- GraphQL introspection, batch abuse, alias brute
- OAuth2: redirect_uri, state manipulation, PKCE downgrade
- CSP bypass: base-uri, nonce leak, JSONP endpoints
- WebSocket hijacking
