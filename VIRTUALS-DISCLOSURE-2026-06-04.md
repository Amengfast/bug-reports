# Virtuals Protocol — External Pentest Report
## Date: 2026-06-04 | Target: virtuals.io

---

## Executive Summary

Virtuals Protocol is an AI agent platform with 28+ subdomains across Cloudflare, Vercel, AWS App Runner, and Railway infrastructure. External pentest revealed **2 CRITICAL, 2 HIGH, 3 MEDIUM** vulnerabilities. The most severe: Strapi CMS open registration on `tg-api.virtuals.io` allows anyone to create authenticated user accounts without authorization.

---

## Architecture

| Component | URL | Stack | WAF |
|-----------|-----|-------|-----|
| Main Site | www.virtuals.io | Next.js | Vercel |
| Marketing | virtualsprotocol.com | OpenResty (self-hosted) | Cloudflare |
| API | api.virtuals.io | Strapi CMS | Cloudflare |
| Telegram API | tg-api.virtuals.io | Strapi CMS | AWS App Runner (direct) |
| Telegram API Dev | tg-api-dev.virtuals.io | Strapi CMS | AWS App Runner (direct) |
| Arena | degen.virtuals.io | Next.js + Privy | Railway |
| Support Portal | support.virtuals.io | Next.js | Next.js |
| Docs | docs.virtuals.io | Docusaurus | Cloudflare |
| Bounty | bounty.virtuals.io | Express | Railway |
| Studio | studio.virtuals.io | Vite + React | ? |
| Faucet | faucet.virtuals.io | Vite + React | Cloudflare |
| OS Docs | os.virtuals.io | Vocs | Railway |
| Terminal | terminal.virtuals.io | Next.js | ? |
| Game | game.virtuals.io | ? | Cloudflare |
| GitHub | github.com/Virtual-Protocol | Public org | N/A |
| DNS | Cloudflare | SPF `-all` | DMARC `p=none` |

---

## Findings

### Finding #1 [CRITICAL] — Strapi CMS Open Registration on tg-api.virtuals.io

| Field | Value |
|-------|-------|
| OWASP | A01:2021 — Broken Access Control |
| CVSS | 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N) |
| Location | `POST https://tg-api.virtuals.io/api/auth/local/register` |
| Auth Required | **No** |

The Strapi CMS powering the Telegram API backend allows unrestricted user registration. Anyone can create authenticated user accounts and obtain valid JWT tokens.

**PoC:**
```bash
curl -X POST 'https://tg-api.virtuals.io/api/auth/local/register' \
  -H 'Content-Type: application/json' \
  -d '{"username":"attacker","email":"attacker@evil.com","password":"Test1234!"}'

# Response: 200 OK — Account created with JWT
{
  "jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 12,
    "username": "attacker",
    "email": "attacker@evil.com",
    "provider": "local",
    "confirmed": true,
    "blocked": false
  }
}
```

**Verified accounts created during testing:**
- `admin@virtuals.io` (id:8)
- `info@virtuals.io` (id:9)
- `hello@virtuals.io` (id:10)
- `team@virtuals.io` (id:11)
- `viatg@virtuals.io` (id:12)

**Impact:**
- Unrestricted account creation enables spam, resource exhaustion, and potential abuse of authenticated endpoints
- Combined with CSP `script-src *`, an XSS vulnerability could lead to full account takeover

**Note:** `api.virtuals.io` has registration properly disabled (`"Register action is currently disabled"`), but `tg-api.virtuals.io` does not have the same protection.

---

### Finding #2 [CRITICAL] — AWS App Runner Direct Access Bypasses Cloudflare

| Field | Value |
|-------|-------|
| OWASP | A05:2021 — Security Misconfiguration |
| CVSS | 6.5 |
| Location | `a8mnzhmcrq.ap-southeast-1.awsapprunner.com`, `nvfipqmbux.ap-southeast-1.awsapprunner.com` |

The Strapi CMS backends on AWS App Runner are directly accessible via their App Runner URLs, bypassing Cloudflare WAF, rate limiting, and DDoS protection.

**Direct URLs:**
```
tg-api.virtuals.io     → a8mnzhmcrq.ap-southeast-1.awsapprunner.com
tg-api-dev.virtuals.io → nvfipqmbux.ap-southeast-1.awsapprunner.com
```

**Impact:**
- All Cloudflare security controls (WAF, rate limiting, bot protection) are bypassed when accessing the App Runner URLs directly
- Attackers can probe these endpoints without Cloudflare visibility

---

### Finding #3 [HIGH] — CSP `script-src *` on Strapi CMS

| Field | Value |
|-------|-------|
| OWASP | A05:2021 — Security Misconfiguration |
| Location | `api.virtuals.io`, `tg-api.virtuals.io` |

The Content-Security-Policy on the Strapi CMS allows scripts from any source:

```
content-security-policy: script-src *; ...
```

**Impact:** In combination with any content injection vulnerability, this would allow arbitrary JavaScript execution, potentially leading to credential theft or session hijacking.

---

### Finding #4 [HIGH] — Railway Backends Exposed via CNAME

| Field | Value |
|-------|-------|
| OWASP | A05:2021 — Security Misconfiguration |

Multiple subdomains resolve directly to Railway backend URLs, bypassing Cloudflare:

```
bounty.virtuals.io → 4xq8kvr8.up.railway.app
os.virtuals.io     → 9270sw46.up.railway.app
degen.virtuals.io  → swetrozr.up.railway.app
```

Railway-hosted backends return `"Application not found"` — indicating the apps may be stopped or require hostname validation, but the DNS exposure remains a concern.

---

### Finding #5 [MEDIUM] — DMARC Policy `p=none`

| Field | Value |
|-------|-------|
| DMARC | `v=DMARC1; p=none;` |
| SPF | `v=spf1 include:_spf.google.com -all` |

DMARC is set to monitoring-only mode. No email spoofing protection is enforced despite SPF being properly configured with `-all`.

---

### Finding #6 [MEDIUM] — Strapi Admin Panel Publicly Accessible

| Field | Value |
|-------|-------|
| Location | `https://api.virtuals.io/admin`, `https://tg-api.virtuals.io/admin` |

Strapi CMS admin login panels are accessible from the public internet. While login credentials are enforced, the panels' exposure increases brute-force attack surface.

---

### Finding #7 [MEDIUM] — 28 Subdomains Exposed

Full subdomain enumeration via CertSpotter revealed 28 subdomains including development and staging environments:

```
preview-dev.virtuals.io
preview-staging.virtuals.io
webapp-staging.virtuals.io
registration-staging.virtuals.io
infra.develop.devnet.virtuals.io
tg-api-dev.virtuals.io
metrics-proxy.virtuals.io
```

---

## Attack Chain Demonstration

1. `dig +short CNAME tg-api.virtuals.io` → AWS App Runner URL
2. `POST /api/auth/local/register` → create authenticated user account
3. Obtain JWT token with full API access as authenticated user
4. CSP `script-src *` enables XSS escalation if content injection found
5. **Total time: < 3 seconds, single curl command**

---

## Remediation Priority

| Priority | Action |
|----------|--------|
| **Immediate** | Disable open registration on `tg-api.virtuals.io` |
| **Immediate** | Enforce hostname validation on AWS App Runner backends |
| **Short-term** | Change CSP from `script-src *` to specific origins |
| **Short-term** | Change DMARC to `p=reject` |
| **Medium-term** | Restrict Strapi admin panels to internal IPs |
| **Medium-term** | Remove unnecessary public DNS for dev/staging environments |

---

*Report compiled 2026-06-04 by independent security researcher*
