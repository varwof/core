# Project Pitch

> **One-line positioning**: Enterprise PKI infrastructure that issues identity cards to AI Agents, all in a 20MB single binary.

---

## Core Demo: 60-Second End-to-End Flow

```
1. Create root CA (USB cold backup)        → varwof init-ca --name Root ...
2. Issue admin certificate (L3 admin)       → varwof issue --ca Mgmt --subject "/CN=ZhangSan/OU=SuperAdmin"
3. Admin logs into Web UI, issues commands in natural language
4. Agent uses temporary certificate for mTLS calls
5. Audit log: "ZhangSan's Agent performed a revocation operation"
```

When demonstrated in a 60-second video, enterprise CTOs immediately understand: **this is the AI governance solution we've been looking for.**

---

## Three World-Class Problems: One Solution

| Problem | Our Solution | Current State of Art |
|---------|-------------|---------------------|
| **Power attribution** | Boss holds root CA private key, delegates via L2/L3 hierarchy | Most enterprises still use shared accounts or web form passwords |
| **AI cannot be held accountable** | Temporary certificate bound to user UID + time/space lock + audit log | 99% of Agents still use static API Keys, cannot distinguish "who is operating" |
| **Admin privilege sprawl** | Permissions written to certificate OU, offline verification | Most systems rely on database RBAC, database compromise = total breach |

> This is not "micro-innovation," this is a **paradigm shift**.

---

## Complete Architecture Loop

```
┌───────────────────────────────────────────────────────────┐
│ User Layer (Boss/Admin)                                    │
│  └─ Holds L3 admin certificate (OU=SuperAdmin / OU=Operator) │
│      ↓ Browser login to Web UI, natural language commands  │
├───────────────────────────────────────────────────────────┤
│ AI Agent Access Layer (pki-agent)                          │
│  └─ Receives commands → sends to LLM → parses intent       │
│  └─ Uses user's "temporary proxy certificate" for mTLS     │
│  └─ Certificate carries X-Agent-User: ZhangSan (user binding)│
│  └─ Time lock + IP lock                                    │
├───────────────────────────────────────────────────────────┤
│ PKI Core Layer (varwof)                                    │
│  └─ Middleware validates mTLS cert OU → maps to RBAC role   │
│  └─ Audit log: "ZhangSan's Agent performed a revocation"   │
│  └─ Business logic execution (issue/revoke/renew/CRL/OCSP) │
│  └─ Returns result to Agent                                │
├───────────────────────────────────────────────────────────┤
│ Infrastructure Layer                                       │
│  └─ Root CA (USB safe) → Management sub-CA (online) → Admin certs │
└───────────────────────────────────────────────────────────┘
```

Every layer is independent, replaceable, and auditable.

---

## Scenario Script (for presentations)

**Opening**:
> "Imagine: your company has 100 AI Agents automatically processing tickets, approval workflows, and code deployments. You don't know which Agent is doing what, or who to blame if something goes wrong. Worse, you can only manage them with shared API Keys. Now, I'm going to use a 20MB binary and a smart card issued to every employee to completely solve this problem. Demo starts..."

**Positioning**:
> "We simultaneously solve pain points for ToB (enterprise services) and ToD (developer ecosystem), finding a rare **'ToG (proving to the era)'** opportunity — letting developers redefine identity and trust in the AI age."

---

## Key Data

- Global PKI market: 2025 **$6.9B** → 2034 **$32.9B** (CAGR 19%)
- China PKI market: 2032 **$4.2B** (CAGR 24.9%)
- Machine identity : Human identity = **80:1**
- Certificate incident rate: **56%** of enterprises experienced outages due to certificate issues
- AI Agent consensus: Keyfactor "No identity, no AI security"
