# DeRouter Network — Coordinated Security Disclosure

**Researcher:** Ameng (jidanameng@gmail.com)  
**Contact:** jidanameng@gmail.com | GitHub: @Amengfast | Telegram: @Lajofastbot  
**Date:** 2026-06-03  
**Methodology:** OWASP API Security Top 10 (2023) + black-box public recon

---

## TL;DR

DeRouter is an "AI Subscription Marketplace" running on Solana (Devnet). Black-box reconnaissance revealed **3 security findings** including **1 CRITICAL** unauthenticated user data leak: the `/api/providers` endpoint publicly exposes **3,152 provider wallet addresses** with reputation scores, task counts, and pricing data — no authentication required, single `curl` command.

---

## CRITICAL-1: Unauthenticated `/api/providers` endpoint leaks 3,152 user wallets

**Description:** Both `https://api.derouter.network/api/providers` and `https://beta-api.derouter.network/api/providers` return a JSON array of ALL registered provider accounts without requiring authentication.

**Exposed data per provider:**
- `wallet` — Solana wallet address
- `tier` — account tier
- `is_online` — current online status
- `total_tasks` — LLM tasks completed
- `reputation_score` — trust score (50 = new, 100 = trusted)
- `created_at` — ISO 8601 timestamp
- `models` — array of model offerings with prices
- `price_per_1k_tokens` — pricing

**Scale at time of testing:**
- **3,152 providers** on mainnet API
- **474 currently online**
- Activity span: 2026-03-17 to 2026-06-03 (77 days)
- Max total_tasks observed: 4,040 (per provider)

**Sample response (first 3 of 3,152 providers):**
```json
[
  {
    "wallet": "8xfDfqN4vzZrUgs8qfphnAJ4hHFaUq9HUfy81wKmWzWF",
    "tier": 0,
    "is_online": false,
    "total_tasks": 4040,
    "reputation_score": 100,
    "created_at": "2026-04-07T08:36:31.000Z",
    "models": [],
    "model": null,
    "price_per_1k_tokens": null,
    "model_count": 0
  },
  {
    "wallet": "CPbwtc1MMVT6qu5MRuVLSKux62bjeW1HFuFwHQR3rB4T",
    "tier": 0,
    "is_online": false,
    "total_tasks": 0,
    "reputation_score": 50,
    "created_at": "2026-04-17T21:04:33.000Z",
    "models": [
      {"model": "gpt-5.3-codex", "price": 0.175},
      {"model": "gpt-5.4", "price": 0.25},
      {"model": "gpt-5.5", "price": 0.5}
    ],
    "model": "gpt-5.3-codex",
    "price_per_1k_tokens": 0.175,
    "model_count": 3
  }
]
```

**Note on model names:** `gpt-5.3-codex`, `gpt-5.4`, `gpt-5.5` do not appear to correspond to any publicly known OpenAI models as of 2026-06-03. Either DeRouter is using internal custom models, or this is a placeholder/test data, or there may be a potential fraud vector where providers advertise access to non-existent models.

**Impact:**
1. **User enumeration** — 3,152 Solana wallet addresses visible to attackers
2. **Phishing targeting** — attackers know which 474 wallets are active
3. **Competitive intelligence** — pricing, model offerings, and provider activity exposed
4. **Sybil attack enablement** — attackers can target low-reputation providers
5. **Privacy violation** — task counts and creation dates reveal activity patterns
6. **Potential GDPR Article 6/32 violation** — personal/financial data processed without adequate safeguards

**CVSS 3.1:** 7.5 (High) — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`  
**OWASP API Security Top 10 (2023):** API3:2023 — Broken Object Property Level Authorization (BOPLA)  
**CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

**Reproduction (single command, no auth):**
```bash
curl -s "https://api.derouter.network/api/providers" | jq 'length'
# Returns: 3152
```

**Remediation:**
- Add authentication middleware to `/api/providers`
- Filter to only return providers relevant to the requesting user
- Remove sensitive fields (`total_tasks`, `reputation_score`, `created_at`) from public listing
- Implement pagination + rate limiting
- Validate provider model names against an allowlist of actual LLM models

---

## MEDIUM-1: `monitor.derouter.network/api/health` leaks version + commit hash

**Description:** The monitor subdomain (separate from main API) exposes a health check returning exact software version and git commit hash.

```json
{
  "database": "ok",
  "version": "12.4.2",
  "commit": "ebade4c739e1aface4ce094934ad85374887a680"
}
```

**Impact:**
- Attacker can search for CVEs against version `12.4.2`
- Commit hash allows exact code reconstruction
- Reveals internal development cadence

**CVSS 3.1:** 5.3 (Medium)  
**CWE:** CWE-200: Exposure of Sensitive Information

**Reproduction:**
```bash
curl -s "https://monitor.derouter.network/api/health" | jq
```

**Remediation:**
- Remove version + commit from public `/api/health`
- Return only `{"status": "ok"}` for unauthenticated requests
- Move detailed health to authenticated `/api/admin/health`

---

## MEDIUM-2: Subdomain sprawl + mixed hosting (no WAF on direct endpoints)

**Description:** DeRouter has 9+ subdomains with mixed infrastructure. Critical subdomains bypass Cloudflare WAF:

| Subdomain | Server | WAF |
|-----------|--------|-----|
| `api.derouter.network` | Cloudflare | ✅ |
| **`api-direct.derouter.network`** (178.105.208.172) | **nginx (raw)** | ❌ |
| `beta-api.derouter.network` | Cloudflare | ✅ |
| **`beta-api-direct.derouter.network`** (178.105.208.172) | **nginx (raw)** | ❌ |
| **`ws.derouter.network`** (46.225.155.88) | **nginx (raw)** | ❌ |
| **`beta-ws.derouter.network`** (46.225.155.88) | **nginx (raw)** | ❌ |
| `monitor.derouter.network` | Cloudflare | ✅ |
| `brainstorm.derouter.network` | Cloudflare (502) | ✅ |

**Impact:**
- Infrastructure exposure — attacker knows hosting provider, IP range
- WAF bypass — attacker can hit `api-direct.derouter.network` to skip CF rate limits, bot detection
- The `/api/providers` leak is on BOTH the CF-fronted `api.derouter.network` AND the raw `api-direct.derouter.network`

**CVSS 3.1:** 5.3 (Medium)  
**CWE:** CWE-668: Exposure of Resource Through Wrong Scope

**Remediation:**
- Remove `api-direct.derouter.network` and `beta-api-direct.derouter.network` DNS records
- Or put them behind Cloudflare (or another WAF)
- Remove `ws.derouter.network` / `beta-ws.derouter.network` direct access; route via CF tunnel

---

## Other Findings (LOW/INFO)

- **No SPF/DMARC/MX records** on derouter.network — phishing risk
- **No `security.txt`** — no security contact channel
- **No VDP** — no vulnerability disclosure program

---

## Technologies Identified

- **Frontend:** Next.js 15 (App Router) + Turbopack
- **Auth:** Privy (embedded wallets, OAuth, MFA)
- **Wallets:** Coinbase Wallet + WalletConnect + Farcaster signers
- **Onramp:** Coinbase Onramp + Moonpay
- **Backend:** Express.js on nginx
- **Settlement:** Solana (Devnet beta, Mainnet TBD)
- **CAPTCHA:** oxlib.sh (human verification)

---

## Coordinated Disclosure

- **Report drafted:** 2026-06-03
- **Contact channels (no security.txt found):**
  - X/Twitter: [@derouter_net](https://x.com/derouter_net) (DM)
  - Telegram: [@derouter_ai](https://t.me/derouter_ai)
- **Suggested disclosure window:** 30 days from submission
- **Researcher:** Ameng (jidanameng@gmail.com)
- **Available for:** clarification, additional reproduction, alternative disclosure channel

---

*Generated 2026-06-03, OWASP API Security Top 10 (2023) methodology. All findings verified using only public information and unauthenticated requests.*
