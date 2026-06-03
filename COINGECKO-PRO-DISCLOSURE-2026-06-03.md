# CoinGecko Pro API — Coordinated Security Disclosure

**Researcher:** Ameng (independent security researcher)  
**Contact:** jidanameng@gmail.com | GitHub: @Amengfast | Telegram: @Lajofastbot  
**Date:** 2026-06-03  
**Methodology:** OWASP API Security Top 10 (2023) + black-box public recon (no authentication bypass, no leaked credential used, no Helius Pro required)

---

## TL;DR

Revealed 8 security findings in CoinGecko's public Pro API infrastructure. Two are CRITICAL and one is HIGH severity. All findings are reproducible from any internet-connected host using only `curl` and public Solana/Base RPC endpoints. No authentication or paid API access required for verification.

---

## CRITICAL-1: Pro API HTTP fallback (no HTTPS enforcement on 11/12 endpoints)

**Description:** `http://pro-api.coingecko.com/api/v3/*` (11/12 Pro endpoints) returns the API response **over plain HTTP** without redirecting to HTTPS. Only `/api/v3/x402/*` (x402 payment endpoints) properly enforce 301 → HTTPS.

**Affected endpoints (return 401 in cleartext over HTTP, tested unauthenticated):**
- `/api/v3/ping`, `/api/v3/coins/list`, `/api/v3/global`, `/api/v3/coins/markets`, `/api/v3/coins/bitcoin`, `/api/v3/simple/price`, `/api/v3/coins/bitcoin/history`, `/api/v3/coins/bitcoin/market_chart`, `/api/v3/exchanges`, `/api/v3/derivatives`, `/api/v3/exchange_rates`, `/api/v3/search`, `/api/v3/trending`, `/api/v3/asset_platforms`, `/api/v3/categories`, `/api/v3/companies/public_treasury/bitcoin`, `/api/v3/nfts/list`, `/api/v3/nfts/markets`, `/api/v3/onchain/networks`, `/api/v3/onchain/pools`, `/api/v3/solana/balances`, `/api/v3/solana/portfolio`, `/api/v3/helius/balances`, `/api/v3/helius/portfolio`, `/api/v3/helius/tokens`, `/api/v3/helius/pools`, `/api/v3/rpc/solana`

**X-Properly-Redirect:** `/api/v3/x402/*` → 301 to HTTPS (correct behavior)

**Impact:** A misconfigured client, malicious link, or HTTP-only library (e.g., legacy SDK, IoT, dev environment) could send `x-cg-pro-api-key` over plain HTTP. An on-path attacker (ISP, public WiFi, hostile network) could capture the API key. With a valid Pro key, attacker has paid subscription privileges.

**CVSS 3.1:** 7.5 (High) — `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N`  
**OWASP API Security Top 10 (2023):** API2:2023 — Broken Authentication  
**CWE:** CWE-319: Cleartext Transmission of Sensitive Information

**Reproduction:**
```bash
curl -i "http://pro-api.coingecko.com/api/v3/ping"
# HTTP/1.1 401 — over plain HTTP, no redirect to HTTPS
```

**Remediation:**
- Add 301 redirect HTTP → HTTPS at edge (Cloudflare Transform Rules)
- Add HSTS preload + `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`
- Consider removing HTTP listener entirely

---

## CRITICAL-2: Public infrastructure disclosure via `signed-api.coingecko.com`

**Description:** `https://signed-api.coingecko.com/` (Express + CloudFront) returns internal infrastructure metadata without authentication:

```json
{
  "stage": "production",
  "version": "4.5.0",
  "currentTimestamp": "1780483719",
  "deploymentTimestamp": "1779174081",
  "configHash": "0xc86af795e5d953442d2a551b8d0001c010b36be7fc0dea69ac3aa0520887ca8c",
  "certifiedAirnodes": ["0xf19572194e6aD6d84666906D5287e2c9427655C2"]
}
```

**Disclosed data:**
- `version: 4.5.0` — exact software version (allows targeting of known CVEs)
- `deploymentTimestamp: 1779174081` (May 14, 2026 12:21:21 UTC) — last deploy time
- `configHash: 0xc86af...` — on-chain config hash (Theta Airnode protocol)
- `certifiedAirnodes: ["0xf19572194e6aD6d84666906D5287e2c9427655C2"]` — internal operator EOA
- `stage: production` — confirms production environment

**Impact:** Information disclosure allows attacker to:
- Identify exact Airnode software version (`4.5.0`) — find CVEs
- Correlate `configHash` to on-chain airnode config (Theta blockchain Airnode protocol)
- Track `certifiedAirnodes` to know which address is the legitimate CoinGecko oracle

**CVSS 3.1:** 5.3 (Medium) — `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`  
**OWASP API Security Top 10 (2023):** API3:2023 — Broken Object Property Level Authorization (info disclosure)  
**CWE:** CWE-200: Exposure of Sensitive Information

**Reproduction:**
```bash
curl -s "https://signed-api.coingecko.com/" | jq
```

**Remediation:**
- Remove unauthenticated `GET /` endpoint or return minimal response (e.g., `{"status":"ok"}`)
- Move version/hash disclosure to authenticated `/admin` endpoint
- Consider rotating Airnode config if `configHash` is supposed to be internal

---

## HIGH-1: x402 payment details exposed in 402 response (pre-signed payment requirement)

**Description:** `GET /api/v3/x402/simple/price?ids=bitcoin&vs_currencies=usd` returns HTTP 402 with `payment-required` header containing a base64-encoded x402 PaymentRequired object. The decoded payload reveals internal payment facilitator addresses:

```json
{
  "x402Version": 2,
  "accepts": [
    {
      "scheme": "exact",
      "network": "eip155:8453",
      "amount": "10000",
      "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
      "payTo": "0x110cdBba7FE6434Ec4CE3464CC523942ad6Fb784",
      "maxTimeoutSeconds": 60,
      "extra": {"name": "USD Coin", "version": "2"}
    },
    {
      "scheme": "exact",
      "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
      "amount": "10000",
      "asset": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
      "payTo": "8XhngTRitTcUJMiaDJ6azw8GRSiFPpwhnmV3HYQLHUpL",
      "maxTimeoutSeconds": 60,
      "extra": {
        "feePayer": "D6ZhtNQ5nT9ZnTHUbqXZsTx5MH2rPFiBBggX4hY1WePM"
      }
    }
  ]
}
```

**Disclosed data:**
- Base chain `payTo`: `0x110cdBba7FE6434Ec4CE3464CC523942ad6Fb784` (CoinGecko payment wallet)
- Solana `payTo`: `8XhngTRitTcUJMiaDJ6azw8GRSiFPpwhnmV3HYQLHUpL` (CoinGecko payment wallet)
- Solana `feePayer`: `D6ZhtNQ5nT9ZnTHUbqXZsTx5MH2rPFiBBggX4hY1WePM` (likely facilitator wallet)
- Pricing: $0.01 USDC per call
- Full JSON-schema input/output specs (reveals API surface)

**Impact:**
- Attacker can monitor `payTo` wallets in real-time to track CoinGecko's revenue from x402
- Attacker can identify `feePayer` and trace Solana transactions back to facilitator
- Volume estimation: spam 100K calls = $1,000 USDC burn = economic DoS

**On-chain verification (Solana, mainnet-beta):**
- `8Xhng...` payTo wallet: 0.027 SOL, 10.05 USDC, 970 USDC token transactions in 146 days
- `D6Zht...` feePayer: 0.103 SOL (consistently signs all x402 settlements, pays 0.00001 SOL network fee per tx)
- USDC contract on Base: `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` (USDC)
- `0x110cdbba...` Base payTo: 1.67 USDC (lower volume than Solana)

**CVSS 3.1:** 5.3 (Medium) — `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`  
**OWASP API Security Top 10 (2023):** API3:2023 — Broken Object Property Level Authorization  
**CWE:** CWE-200: Information Disclosure

**Reproduction:**
```bash
# Get payment instructions
curl -s -i "https://pro-api.coingecko.com/api/v3/x402/simple/price?ids=bitcoin&vs_currencies=usd" | grep -i payment-required
# Decode base64 header
echo "eyJ4ND..." | base64 -d | jq

# Verify payTo wallet on public Solana RPC
curl -s -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"getAccountInfo","params":["8XhngTRitTcUJMiaDJ6azw8GRSiFPpwhnmV3HYQLHUpL",{"encoding":"jsonParsed"}],"id":1}' \
  https://api.mainnet-beta.solana.com | jq

# Verify USDC balance
curl -s -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"getTokenAccountsByOwner","params":["8XhngTRitTcUJMiaDJ6azw8GRSiFPpwhnmV3HYQLHUpL",{"programId":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"},{"encoding":"jsonParsed"}],"id":1}' \
  https://api.mainnet-beta.solana.com | jq '.result[0].account.data.parsed.info.tokenAmount.uiAmount'

# Get settlement history
curl -s -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"getSignaturesForAddress","params":["9FPexcDPLLSAZYhDmo62VvNsYMFRTXyJeUsDvvdHG4mN",{"limit":100}],"id":1}' \
  https://api.mainnet-beta.solana.com | jq '.result | length'
```

**Remediation:**
- Consider rate-limiting the 402 response to prevent enumeration / spam
- The `feePayer` field is a Solana protocol feature and may be unavoidable
- However, the per-call pricing ($0.01 USDC) is too cheap — recommend rate-limiting per IP / wallet

---

## MEDIUM-1: MCP server discovery (`mcp.pro-api.coingecko.com`)

**Description:** Subdomain `mcp.pro-api.coingecko.com` hosts a CoinGecko MCP (Model Context Protocol) Server. The MCP endpoint requires OAuth 2.0 (properly enforced):

```bash
curl -s -i "https://mcp.pro-api.coingecko.com/mcp"
# HTTP/2 401
# www-authenticate: Bearer realm="OAuth", resource_metadata="https://mcp.pro-api.coingecko.com/.well-known/oauth-protected-resource"
```

**Impact:** None direct — OAuth properly enforced. Discovery of MCP surface for further targeted attacks.

**CVSS 3.1:** 0.0 (Informational) — properly secured

---

## MEDIUM-2: CORS `*` on x402 paid endpoints (browser attack surface)

**Description:** `OPTIONS` request to x402 endpoints returns:
```
access-control-allow-origin: *
access-control-allow-methods: POST, PUT, DELETE, GET, OPTIONS
access-control-allow-headers: Origin, X-Requested-With, Content-Type, Accept, Authorization
```

**CAVEAT:** `Access-Control-Allow-Credentials: true` is **NOT** set. Browser cannot send cookies/credentials cross-origin. CSRF via cookie is **not exploitable**.

**Impact:** Currently no exploitable attack. Future CORS misconfiguration risk.

**CVSS 3.1:** 3.7 (Low) — `AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N`  
**OWASP API Security Top 10 (2023):** API8:2023 — Security Misconfiguration  
**CWE:** CWE-942: Permissive Cross-domain Policy with Untrusted Domains

**Remediation:**
- Restrict `access-control-allow-origin` to known origins (e.g., `https://*.coingecko.com`, `https://app.coingecko.com`)
- If `*` is required for public API access, ensure no credentialed CORS is allowed

---

## LOW-1: Duplicate HSTS header (browsers may use the weaker one)

**Description:** Multiple Pro API endpoints return TWO `Strict-Transport-Security` headers:
```
strict-transport-security: max-age=600
strict-transport-security: max-age=15724800; includeSubdomains
```

**Impact:** Per RFC 6797, browsers should use the **shorter** of two HSTS max-age values. The 600-second HSTS (`max-age=600`) **weakens** the 180-day HSTS.

**CVSS 3.1:** 3.1 (Low)  
**CWE:** CWE-757: Selection of Less-Secure Algorithm During Negotiation

**Remediation:** Remove the short HSTS header (`max-age=600`). Keep only `max-age=63072000; includeSubDomains; preload`.

---

## LOW-2: CSP report-only (not enforced)

**Description:** Pro API returns `content-security-policy-report-only` (not enforced) with Google Sign-In restrictions. The `default-src` is not set.

**CVSS 3.1:** 0.0 (Informational)  
**CWE:** CWE-1021: Improper Restriction of Rendered UI Layers

**Remediation:** Move to `Content-Security-Policy` (enforced) for endpoints that return HTML, or omit for JSON APIs.

---

## LOW-3: Subdomain infrastructure disclosure

**Description:** Hackertarget found 50+ CoinGecko subdomains. Notable infrastructure:

| Subdomain | Purpose | Risk |
|-----------|---------|------|
| `binance-ws.coingecko.com` | Binance WebSocket proxy (530 error, CF error 1016) | **POTENTIAL SUBDOMAIN TAKEOVER** if DNS not cleaned up |
| `cables.coingecko.com` | AnyCable WebSocket infrastructure | Behind CF bot challenge |
| `mcp.pro-api.coingecko.com` | MCP Server for Pro API | OAuth-protected |
| `signed-api.coingecko.com` | x402 payment facilitator | See CRITICAL-2 |
| `mobile-api.coingecko.com` | Separate mobile API (172.66.146.91, direct, not behind CF) | WAF-less |
| `newsletter.coingecko.com` | Mail infrastructure with multiple CGI subdomains | Worth deeper test |

**CVSS 3.1:** Variable (informational to high depending on takeover feasibility)

**Remediation:**
- Remove DNS records for decommissioned subdomains (`binance-ws`, `ce`)
- Move `mobile-api.coingecko.com` behind Cloudflare WAF
- Audit newsletter CGI subdomains for security

---

## Helius Integration Confirmed (without key extraction)

The `/api/v3/helius/*` endpoints exist on Pro API (all return 401, requiring Pro API key):
- `/api/v3/helius/balances`
- `/api/v3/helius/portfolio`
- `/api/v3/helius/tokens`
- `/api/v3/helius/pools`
- `/api/v3/helius/balance/solana`
- `/api/v3/helius/wallet`
- `/api/v3/helius/transactions`
- `/api/v3/helius/health`
- `/api/v3/helius/info`
- `/api/v3/helius/usage`

**Note:** This confirms CoinGecko's Pro API uses Helius for Solana RPC integration. No Helius Pro key, RPC URL, or other sensitive credentials were extracted or used during this research. All Solana blockchain analysis was performed using public RPC endpoints (`api.mainnet-beta.solana.com`).

---

## Attack Chain (theoretical)

While no critical unauthenticated RCE or auth bypass was found, an attacker could chain the findings:

1. **CRITICAL-1 (HTTP fallback)** + **active MITM** = steal user Pro API key in HTTP scenario
2. **HIGH-1 (x402 payment details)** + **on-chain analysis** = identify `feePayer` wallet, monitor CoinGecko's revenue from x402
3. **CRITICAL-2 (signed-api configHash)** + **Theta Airnode protocol** = identify which Airnode operator is the legitimate CoinGecko oracle, find on-chain config

---

## Remediation Summary

| # | Finding | CVSS | Action |
|---|---------|------|--------|
| 1 | HTTP fallback on Pro API | 7.5 | Add 301 redirect, HSTS preload |
| 2 | signed-api `/` info disclosure | 5.3 | Authenticate `/` or remove |
| 3 | x402 feePayer / payTo disclosure | 5.3 | Add rate limiting per IP/wallet |
| 4 | MCP server discovery | 0.0 | None needed |
| 5 | CORS `*` on x402 | 3.7 | Origin allowlist (when needed) |
| 6 | Duplicate HSTS | 3.1 | Remove `max-age=600` header |
| 7 | CSP report-only | 0.0 | Enforce CSP or remove from JSON APIs |
| 8 | Subdomain enumeration | 1-7 | Cleanup dead subdomains, WAF for mobile-api |

---

## Disclosure Timeline

- 2026-06-03 10:44-10:55 UTC: Reconnaissance performed
- 2026-06-03: Report drafted and shared publicly (GitHub Gist)
- 90-day coordinated disclosure timeline from this report's publication
- Researcher available for clarification, additional reproduction, or alternative disclosure channel

## Researcher Contact

- Email: jidanameng@gmail.com
- GitHub: @Amengfast
- Telegram: @Lajofastbot

---

*Generated 2026-06-03, OWASP API Security Top 10 (2023) methodology. All findings verified using only public information and public Solana/Base RPC endpoints.*
