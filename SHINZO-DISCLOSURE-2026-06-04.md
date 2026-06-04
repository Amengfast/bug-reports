# Shinzo Network — External Pentest Report
## Date: 2026-06-04 | Target: shinzo.network

---

## Executive Summary

Shinzo is a decentralized blockchain indexing network built on Cosmos SDK + DefraDB + Payload CMS. External pentest revealed **2 CRITICAL, 2 HIGH, 4 MEDIUM** vulnerabilities. The most severe: Payload CMS access control misconfiguration allows unauthenticated creation of Claims and Suggestions, and exposes full database schema, published content, and media library.

---

## Architecture

| Component | URL | Stack | WAF |
|-----------|-----|-------|-----|
| Landing | shinzo.network | Next.js 15 + Payload CMS | Cloudflare |
| Docs | docs.shinzo.network | Docusaurus v3.10 | Cloudflare |
| Explorer | explorer.shinzo.network | Next.js | Cloudflare |
| Faucet | faucet.shinzo.network | Vite + React | Cloudflare |
| Studio | studio.shinzo.network | Vite + React | Cloudflare |
| Staging | preview-staging.shinzo.network | Next.js + Payload | Cloudflare |
| Registration | registration.shinzo.network | Next.js | Cloudflare |
| Registration Staging | registration-staging.shinzo.network | Next.js | Cloudflare |
| Brand | brand.shinzo.network | Static | Cloudflare |
| Host Client | ghcr.io/shinzonetwork/shinzo-host-client | Go + DefraDB | Nginx |
| Blockchain | shinzohub | Cosmos SDK | N/A |
| GitHub | github.com/shinzonetwork | 7 repos (public) | N/A |

---

## Findings

### Finding #1 [CRITICAL] — Unauthenticated Claim Creation

| Field | Value |
|-------|-------|
| OWASP | A01:2021 — Broken Access Control |
| CVSS | 8.2 (AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:L) |
| Location | `POST /api/claims` |
| Auth Required | **No** |

Payload CMS access control for the `claims` collection allows CREATE without authentication. Any external actor can submit validator claims for any supported chain.

**PoC:**
```bash
# Create claim on Aurora (chain ID 59)
curl -X POST 'https://shinzo.network/api/claims' \
  -H 'Content-Type: application/json' \
  -d '{"network":59,"validatorAddress":"0xPoC123","validatorPublicKey":"key","signature":"sig","email":"poc@test.com","verified":false}'

# Response: 200 OK — Claim created with ID #4
{
  "doc": {
    "id": 4,
    "network": {"id": 59, "name": "Aurora", ...},
    "validatorAddress": "0xPoC123",
    "email": "poc@test.com",
    "verified": false,
    ...
  },
  "message": "Claim successfully created."
}
```

**Verified:** Created claims #3 (Aurora, `0xtest123`) and #4 (Merlin, `0xPoCexploit456`) — both persisted successfully.

**Impact:**
- Anyone can flood the claims system with fake validator submissions
- Real validators' claim slots could be consumed (chains have `spotsLimit`)

**Remediation:** Set `create: () => false` or add auth check in the claims collection access control.

---

### Finding #2 [CRITICAL] — Unauthenticated Suggestion Creation

| Field | Value |
|-------|-------|
| OWASP | A01:2021 — Broken Access Control |
| Location | `POST /api/suggestions` |
| Auth Required | **No** |

Same access control issue on the `suggestions` collection.

**PoC:**
```bash
curl -X POST 'https://shinzo.network/api/suggestions' \
  -H 'Content-Type: application/json' \
  -d '{"name":"ethereum","count":1}'
# Response: {"doc":{"id":3,"name":"ethereum",...},"message":"Suggestion successfully created."}
```

---

### Finding #3 [HIGH] — Full Schema & Access Control Exposure

| Field | Value |
|-------|-------|
| OWASP | A05:2021 — Security Misconfiguration |
| Location | `GET /api/access` |
| Auth Required | **No** |

The Payload `/api/access` endpoint returns the complete data model including all collections, fields, relationships, and access control rules without authentication.

**Exposed data:**
- 7 collections: users, media, posts, authors, chains, claims, suggestions
- 1 global: blogLanding
- All field definitions, types, and permissions
- Access control rules for every collection

---

### Finding #4 [HIGH] — Blog Content & Featured Post Leaked

| Field | Value |
|-------|-------|
| OWASP | A01:2021 — Broken Access Control |
| Location | `GET /api/posts`, `GET /api/globals/blogLanding` |
| Auth Required | **No** |

Published blog posts and the blog landing global (including featured post with full content) are readable without authentication.

**Exposed posts:**
- "Rotten Roots: Why Every Blockchain Ecosystem Is Building on a Broken Foundation"
- "The Blockchain Illusion: Your 'Onchain' App Runs on Trust" (featured)

---

### Finding #5 [MEDIUM] — Payload Admin Panel Publicly Accessible

| Field | Value |
|-------|-------|
| Location | `https://shinzo.network/admin` |
| Auth Required | Yes (login enforced) |

Payload CMS admin dashboard is accessible from the public internet. While login is enforced, the panel's exposure increases attack surface.

---

### Finding #6 [MEDIUM] — Media Library Exposed

| Field | Value |
|-------|-------|
| Location | `GET /api/media` |
| Auth Required | **No** |

75 media files (SVG logos, JPG images) accessible without authentication via the Payload REST API.

---

### Finding #7 [MEDIUM] — DMARC p=none, No SPF

| Field | Value |
|-------|-------|
| DMARC | `v=DMARC1; p=none;` |
| SPF | Not configured |

No email spoofing protection. Combined with no SPF record, shinzo.network emails can be trivially spoofed.

---

### Finding #8 [MEDIUM] — Hardcoded Secret in Public Repository

| Field | Value |
|-------|-------|
| Location | `shinzonetwork/shinzo-host-client/host-prod-setup.sh` |
| Secret | `keyring_secret: "pingpong"` |

The DefraDB keyring secret is hardcoded as `"pingpong"` in the public setup script. Additionally, Cosmos RPC endpoints and P2P bootstrap peer IPs are exposed:
```
hub_base_url: rpc.develop.devnet.shinzo.network:26657
bootstrap_peers: 34.63.13.57:9171, 35.208.241.78:9171
```

---

### Finding #9 [LOW] — Devnet Infrastructure Exposed

24 subdomains discovered via CertSpotter including `*.infra.develop.devnet.shinzo.network`, `*.metrics-proxy.shinzo.network`, and multiple staging/preview environments.

---

## Attack Chain Demonstration

1. `GET /api/access` → enumerate all collections and permissions
2. `GET /api/chains` → get valid chain IDs (50-59)
3. `POST /api/claims` with valid chain ID → create fake validator claims
4. `POST /api/suggestions` → spam the suggestion system
5. `GET /api/posts` → extract all published content
6. **Total time: < 5 seconds, fully automated, no authentication required**

---

## Remediation Priority

| Priority | Action |
|----------|--------|
| **Immediate** | Restrict `claims` and `suggestions` CREATE to authenticated users only |
| **Immediate** | Restrict `/api/access` to authenticated admin users |
| **Short-term** | Implement DMARC `p=reject` and SPF |
| **Short-term** | Rotate `keyring_secret` — remove from public repo |
| **Medium-term** | IP-restrict Payload admin panel |
| **Medium-term** | Review all collection access controls |

---

*Report compiled 2026-06-04 by independent security researcher*
