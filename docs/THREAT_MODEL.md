# Threat model

## Scope

This threat model covers repository input integrity, deterministic local/CI
simulation, report evidence, and the local dashboard. It excludes real incident
execution because the project has no such capability.

## Assets

- integrity of the topology, profiles, scenario, metrics, and event chains;
- truthfulness of the no-external-effects safety boundary;
- reproducibility of before/after claims;
- confidentiality of unrelated host files and paths;
- availability of the bounded local service.

The packaged enterprise and all data volumes are fictional. There are no secrets,
credentials, production logs, or executable samples.

## Actors and boundaries

1. A contributor can propose untrusted repository content.
2. CI validates that content before review.
3. A local operator runs reviewed packaged content.
4. A browser can request only known profiles from the loopback API.

## Threats and controls

| Threat | Control |
|---|---|
| Input substitution | Per-file SHA-256 integrity manifest |
| Parser ambiguity | Duplicate-key and unknown-field rejection |
| Path/symlink escape | Canonical path containment |
| Action smuggling | Exact schema and six-value primitive enum |
| Dangling/forged graph reference | Asset/path/dependency referential validation |
| Stage reordering | Monotonic stage and deterministic action ordering |
| Shell/process abuse | No runtime execution imports; AST safety gate |
| Network egress | No outbound-client imports; counter-only egress model |
| Destructive host I/O | No delete/rename/unlink runtime calls |
| Evidence alteration | Canonical functional digest, golden file hashes, event chains |
| Browser injection/clickjacking | Text-only DOM updates, CSP, nosniff, frame denial |
| API abuse | Loopback default, exact schemas, 16 KiB cap, no uploads |
| Container privilege | Non-root, read-only root, dropped capabilities, limits |
| Supply-chain drift | Standard-library runtime, pinned build tools/image/actions |

## Residual risks

- SHA-256 establishes identity relative to trusted metadata, not author identity.
- A contributor changing code and golden data together still requires human review
  of changed assumptions and metrics.
- Event chains are tamper-evident rather than externally signed or append-only.
- The unauthenticated local server is unsuitable for direct exposure to an
  untrusted network.
- Large concurrent API requests can consume CPU despite body limits; production
  multi-tenancy would require queues, quotas, authentication, and isolation.
