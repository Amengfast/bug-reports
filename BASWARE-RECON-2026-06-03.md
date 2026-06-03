# Basware — External Pentest Recon
## Date: 2026-06-03
## Target: basware.com (AP Automation SaaS)

---

## Architecture Overview

| Layer | Host | Stack | CDN/WAF | Auth |
|-------|------|-------|---------|------|
| Corporate | www.basware.com | HubSpot CMS (portal 2999407) | Cloudflare | None |
| Product Portal | portal.basware.com | Java Play Framework + Knockout.js | AWS Global Accelerator | Cognito |
| Admin (Guardian) | admin.basware.com | Angular 20 + Native Federation | CloudFront + S3 | Cognito |
| Access/Auth | access.basware.com | Angular 20 Material | CloudFront + S3 | Cognito |
| Access API | api.access.basware.com | AWS API Gateway | Cloudflare | Cognito JWT |
| Admin API (EU) | prod-euproxy.admin.services.basware.com | AWS API Gateway | — | Cognito JWT |
| Admin API (US) | prod-usproxy.admin.services.basware.com | AWS API Gateway | — | Cognito JWT |
| Admin API (AU) | prod-auproxy.admin.services.basware.com | AWS API Gateway | — | Cognito JWT |
| Admin API (CA) | prod-caproxy.admin.services.basware.com | AWS API Gateway | — | Cognito JWT |
| ServiceNow | basware.service-now.com | ServiceNow Yokohama | F5 BIG-IP | LDAP |
| FTP | ftp.basware.com (52.215.125.170) | CrushFTP | — | Required |
| Billing | billing.basware.com | AWS ELB | — | Unknown |
| Confluence | confluence.basware.com | AWS ELB (eu-west-1) | — | Atlassian |
| Jira | jira.basware.com → basware.atlassian.net | Atlassian Cloud | Cloudflare | Atlassian |

## Dev/Test Environments (Publicly Accessible)

| Env | URL | Stack | Protection |
|-----|-----|-------|-----------|
| DEV Admin | admin.baswaredev.com | Angular (production:false) | CloudFront |
| DEV Access | access.baswaredev.com | Angular | CloudFront |
| DEV API | api.access.baswaredev.com | API Gateway | Cloudflare |
| DEV Proxy | dev-euproxy.admin.services.baswaredev.com | API Gateway | EC2 direct |
| TEST Admin | test-admin.basware.com | Angular | CloudFront |
| TEST Access | accesstest.basware.com | Angular | S3 DIRECT (no CDN) |
| TEST API | api.access.basware.com (shared) | API Gateway | Cloudflare |
| TEST Proxy | test-euproxy.admin.services.basware.com | API Gateway | EC2 direct |

## Technologies Identified
- Angular 20.3.18 (with Native Federation)
- Java Play Framework (portal, path: /opt/onp-front)
- Java 17.0.18 (ServiceNow)
- Tomcat (ServiceNow)
- AWS Cognito (6 regions)
- AWS API Gateway
- AWS CloudFront + S3
- AWS Global Accelerator
- AWS ELB
- HubSpot CMS (portal ID: 2999407)
- F5 BIG-IP (ServiceNow)
- Knockout.js 3.4.2 (portal)
- RequireJS (portal)
- AG Grid Enterprise (admin)
- CrushFTP (ftp)
- Atlassian Cloud (Jira)
- Microsoft 365 (email)

## DNS Records
- NS: dns1.stabletransit.com, dns2.stabletransit.com
- MX: basware-com.mail.protection.outlook.com
- SPF: Present with -all (strict)
- DMARC: NOT PRESENT
- CAA: NOT PRESENT

## Cognito Regions (from CSP)
- cognito-idp.eu-west-1.amazonaws.com
- cognito-idp.us-west-2.amazonaws.com
- cognito-idp.us-east-1.amazonaws.com
- cognito-idp.us-east-2.amazonaws.com
- cognito-idp.ap-southeast-2.amazonaws.com
- cognito-idp.ca-central-1.amazonaws.com
