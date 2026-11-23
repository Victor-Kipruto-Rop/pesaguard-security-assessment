# PesaGuard Security Assessment

A permission-first security assessment toolkit for authorized PesaGuard local and staging environments. The initial release focuses on safe, bounded, evidence-backed checks. Production targets are read-only by default.

> **Status:** Initial implementation in progress. Do not treat this repository as a certification or as proof that a target is secure.

## Safety contract

- Assess only systems you own or have explicit written authorization to test.
- Enroll each target with an exact hostname, environment, allowed checks, expiry, and approval record.
- Default checks are non-destructive and rate-limited. No credential stuffing, brute force, exploit chaining, persistence, destructive payloads, or real-money transactions.
- State-changing transaction and tenant-isolation tests require staging plus synthetic fixtures and explicit approval.
- Never commit credentials, customer data, production tokens, or real Daraja secrets.

## Planned implementation

Python 3.12+, FastAPI, Pydantic, HTTPX, pytest, structured JSON/HTML reporting, deterministic policy enforcement, and local Docker support.

See `docs/SAFETY.md`, `docs/QUICKSTART.md`, and `docs/ARCHITECTURE.md` as the implementation lands.