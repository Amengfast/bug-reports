# Basware — Vulnerability Findings
## Date: 2026-06-03 | Classification: External Pentest
## Contact: security@basware.com

---

## Finding #1 [CRITICAL] — ServiceNow System Monitoring Unauthenticated

| Field | Value |
|-------|-------|
| OWASP Category | A01:2021 — Broken Access Control |
| CVSS 3.1 | 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N) |
| Location | basware.service-now.com |
| Auth Required | No |

### Description
Multiple ServiceNow diagnostic endpoints are accessible without authentication, exposing detailed system metrics, Java thread dumps, and internal infrastructure information.

### Unauthenticated Endpoints
1. `/stats.do` — Full system dashboard
2. `/threads.do` — Complete Java thread dump
3. `/background_progress_worker.do` — Worker pool details
4. `/welcome.do` — ServiceNow main shell
5. `/service_catalog.do` — Catalog shell
6. `/sys_attachment.do` — Attachment processor

### Impact (from `/stats.do`)
- **System Memory**: 1963MB max, 12% free (1733MB in use)
- **Transactions**: 9,134,814 total, 87,737 errors handled
- **Sessions**: 163 logged in (335 active), max concurrency 1,918
- **32 Database Connections** — individual utilization % + age per connection
- **Internal cluster**: `app131160.ams201.service-now.com:basware015`
- **Scheduler**: `app128051.ams201.service-now.com:basware017`
- **Build**: Yokohama patch12-hotfix1a (04-02-2026)
- **Java**: 17.0.18, **Tomcat**: http-nio2-16040
- **Semaphore per module**: Default(16), Debug(4), AMB_RECEIVE, TRINO_REST, API_INT, Presence

### Impact (from `/threads.do`)
- Full thread dump with internal class paths:
  - `com.glide.sys.*`, `com.glide.ais.*`, `com.glide.schedule_v2.*`, `com.glide.outbound.*`
  - `com.glide.cluster.ClusterSynchronizer`
  - `com.glide.sys.lock.LockSweeper`
  - `com.glide.ais.ha.partition.PartitionHealthStatusProcessor`

### PoC
```bash
# System stats
curl -s "https://basware.service-now.com/stats.do" | grep -E "Max memory|Transactions|Logged in|Build|Instance|Cluster"

# Thread dump
curl -s "https://basware.service-now.com/threads.do"
```

### Remediation
Require authentication for all diagnostic endpoints. At minimum, restrict `/stats.do`, `/threads.do`, `/background_progress_worker.do`, and `/sys_attachment.do` to authenticated administrative users only.

---

## Finding #2 [HIGH] — AG Grid Enterprise License Key Exposed in Client-Side JavaScript

| Field | Value |
|-------|-------|
| OWASP Category | A04:2021 — Insecure Design |
| CVSS 3.1 | 6.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N) |
| Location | admin.basware.com, admin.baswaredev.com |
| Auth Required | No |

### Description
A full AG Grid Enterprise license key is hardcoded in the client-side JavaScript bundle of the admin application. The key is visible to anyone loading the application.

### Affected Files
- `https://admin.basware.com/main-J7PVGYCN.js` (PROD)
- `https://admin.baswaredev.com/chunk-GSGZP6X5.js` (DEV)

### License Details Extracted
- License ID: AG-087447
- Licensee: Basware Oy
- Application: Guardian
- Type: Single Application Developer License
- Developers: 2 Front-End JavaScript developers
- Deployment Add-on: 1 Production Environment
- Version cap: AG Grid Enterprise versions before June 2, 2026

### Impact
- License can be extracted and reused by unauthorized parties
- Violates AG Grid licensing terms
- Exposes internal project name ("Guardian") not visible elsewhere

### PoC
```bash
curl -s "https://admin.basware.com/main-J7PVGYCN.js" | grep -o "LicenseManager.setLicenseKey.*"
```

### Remediation
Move the license key to a server-side configuration or environment variable. Do not bundle license keys in client-side JavaScript.

---

## Finding #3 [HIGH] — Dev/Test Environments Publicly Accessible

| Field | Value |
|-------|-------|
| OWASP Category | A05:2021 — Security Misconfiguration |
| CVSS 3.1 | 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N) |
| Location | Multiple subdomains |
| Auth Required | No (to access apps); Cognito (for functionality) |

### Description
Multiple development and testing environments are publicly accessible from the internet. The DEV admin runs in Angular development mode (`production:false`).

### Affected Environments
1. `admin.baswaredev.com` — DEV Admin (production:false, debug mode)
2. `test-admin.basware.com` — TEST Admin
3. `access.baswaredev.com` — DEV Access/Auth
4. `accesstest.basware.com` — TEST Access (S3 direct, **no CDN/WAF**)
5. `api.access.baswaredev.com` — DEV Access API

### Impact
- DEV admin runs in debug mode enabling Angular dev tools and verbose error messages
- `accesstest.basware.com` served directly from S3 without CloudFront/Cloudflare WAF
- Configuration differences between environments may introduce additional attack surface

### Remediation
- Place dev/test environments behind IP whitelisting or VPN
- Enable production mode on all publicly accessible Angular applications
- Route `accesstest.basware.com` through CloudFront/WAF

---

## Finding #4 [HIGH] — Full Infrastructure Map Exposed in Client JavaScript

| Field | Value |
|-------|-------|
| OWASP Category | A04:2021 — Insecure Design |
| CVSS 3.1 | 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N) |
| Location | admin.basware.com |
| Auth Required | No |

### Description
The admin application JavaScript bundle contains the complete environment configuration including all backend API proxy URLs for development, testing, and production.

### Information Exposed
```javascript
// PROD
app_base_url: "https://admin.basware.com"
proxyApi: "https://prod-euproxy.admin.services.basware.com"
proxyApi_us: "https://prod-usproxy.admin.services.basware.com"
proxyApi_au: "https://prod-auproxy.admin.services.basware.com"
proxyApi_ca: "https://prod-caproxy.admin.services.basware.com"
bw_access_url: "https://access.basware.com"

// TEST
app_base_url: "https://test-admin.basware.com"
proxyApi: "https://test-euproxy.admin.services.basware.com"
proxyApi_us: "https://test-usproxy.admin.services.basware.com"
bw_access_url: "https://accesstest.basware.com"

// DEV
app_base_url: "https://admin.baswaredev.com"
proxyApi: "https://dev-euproxy.admin.services.baswaredev.com"
bw_access_url: "https://access.baswaredev.com"

// LOCAL
app_base_url: "http://localhost:4200"
proxyApi: "https://localhost:5001"
```

### Impact
Provides attacker with complete internal API topology, reducing recon effort to near zero.

### Remediation
Do not bundle environment-specific configurations in client-side code. Load configuration server-side or via authenticated API endpoint.

---

## Finding #5 [HIGH] — No DMARC Policy

| Field | Value |
|-------|-------|
| OWASP Category | A05:2021 — Security Misconfiguration |
| CVSS 3.1 | 5.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N) |
| Location | basware.com DNS |
| Auth Required | No |

### Description
basware.com has no DMARC DNS record. Combined with the existing SPF record (which uses `-all`), this gap leaves the domain vulnerable to email spoofing attacks that bypass SPF-only validation.

### Impact
- Attackers can send spoofed emails appearing to come from @basware.com
- No mechanism for receiving domain to verify authenticity beyond SPF
- Increased phishing risk for Basware customers and partners

### Remediation
Implement a DMARC policy. Start with `p=none` for monitoring:
```
_dmarc.basware.com. IN TXT "v=DMARC1; p=none; rua=mailto:dmarc@basware.com"
```

---

## Finding #6 [MEDIUM] — Server Environment Info Leak

| Field | Value |
|-------|-------|
| OWASP Category | A05:2021 — Security Misconfiguration |
| Location | portal.basware.com |

### Description
The portal application leaks internal server environment details in HTML responses:
```
jquery.onp.environment = "Environment(/opt/onp-front,jdk.internal.loader.ClassLoaders$AppClassLoader@21588809,Prod)";
```

This exposes: server filesystem path, Java classloader type and memory address, and environment role.

### Remediation
Remove environment information from production HTML responses.

---

## Finding #7 [MEDIUM] — Debug Console.log in Production JavaScript

| File | `access.basware.com/main-73JR6DZT.js` |
|-------|----------------------------------------|

Multiple `console.log` statements with `location.hostname.includes("baswaredev")` guards are present in the production Access app bundle. While gated, these increase the attack surface if a developer ever accesses production with a dev hostname.

---

## Finding #8 [MEDIUM] — RequestedService Parameter 502 Responses

The `requestedService` parameter on the portal login flow (`/access?requestedService=`) returns HTTP 502 for path traversal payloads instead of proper 400/403 validation errors, suggesting backend exception handling for malformed input.

---

## Finding #9 [INFO] — FTP Server Exposed

`ftp.basware.com` (52.215.125.170:21) is accessible from the internet. Anonymous login disabled. Server appears to be CrushFTP.

---

## Prioritized Remediation

### Immediate (7 days)
1. Restrict ServiceNow `/stats.do` and `/threads.do` to authenticated admin users
2. Implement DMARC policy
3. Restrict dev/test environments to internal/VPN access only

### Short-term (14 days)
4. Remove AG Grid license key from client-side JavaScript
5. Remove environment configuration from client-side bundles
6. Remove server environment info from production responses

### Medium-term (30 days)
7. Implement IP whitelisting for all non-production environments
8. Enable production mode on `admin.baswaredev.com`
9. Route `accesstest.basware.com` through CDN/WAF
10. Clean up debug console.log statements in production bundles

---

## Methodology
- Passive recon: DNS enumeration, certificate transparency, HTTP header analysis
- Active recon: Subdomain enumeration, API discovery, JavaScript bundle analysis
- Service enumeration: Endpoint discovery, parameter fuzzing, GraphQL probing
- Browser-based: Network request interception, Angular state inspection

## Limitations
- No authenticated testing performed (no Cognito credentials available)
- Backend API testing limited to unauthenticated endpoints
- No social engineering or phishing vectors explored

---

*Report compiled 2026-06-03 by independent security researcher*
