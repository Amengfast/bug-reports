# Critical Security Findings — Kodiak Finance
**Reporter:** Amengfast  
**Date:** June 3, 2026  
**Severity:** CRITICAL

## Summary

Multiple backend API endpoints at `backend.kodiak.finance` and `bots-api.kodiak.finance` expose sensitive financial data **without any authentication**.

## Affected Endpoints

| Endpoint | Data Exposed | Records |
|----------|-------------|---------|
| `GET /orderly/leaderboard` | User addresses, PnL, trading volume, fees, VIP tier | 1,000 |
| `GET /orderly/points` | User addresses, point balances | 621 |
| `GET /orderly/vip-tiers/user/{addr}` | Individual allocation data | Any address |
| `GET /orderly/stats` | Global volume ($1.47B), fees, PnL | — |
| `GET /bots` (bots-api) | Live trading bot config + owner wallet | 1 active |
| `GET /vaults` | 109 vaults, $37M TVL, APR | 109 |
| `GET /farms` | 390 farms, $34.9M TVL, staking tokens | 390 |
| `GET /metrics` | Prometheus metrics + 119 internal routes | 4.8MB |

## Impact

- 1,000 users' PnL, volume, VIP tier exposed → targeted phishing possible
- 621 wallet addresses + point balances leaked → airdrop gaming
- Live trading bot strategy (BTC classic_grid $68K-$83K) + wallet exposed → front-running
- CORS `*` on all backend endpoints
- No SPF/DMARC → email spoofing from @kodiak.finance
- Grafana 13.0.1 unpatched on `grafana.bots-api`

## Remediation

**Immediate:** Add authentication middleware to all `/orderly/*`, `/vaults`, `/farms`, `/bots`, `/metrics` endpoints.  
**Short-term:** Restrict CORS policy, add SPF/DMARC, upgrade Grafana.

## Responsible Disclosure

These findings are reported in good faith. I have not and will not exploit them beyond verification. Full technical report available upon request.
