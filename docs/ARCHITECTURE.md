# Architecture

## Purpose and boundary

The system answers one bounded question: under identical deterministic incident
pressure, how do selected architectural controls change spread, data impact, and
recovery estimates?

It is a state-machine simulator. It does not emulate operating systems, execute
protocols, create processes, alter credentials, encrypt files, or transmit data.

## Components

1. **Integrity bundle** packages the topology, scenario, and five profiles. A
   separate manifest pins every byte with SHA-256.
2. **Contract loader** rejects duplicate keys, unknown fields, invalid types,
   unsupported versions, traversal/symlink escapes, duplicate identifiers,
   dangling graph references, invalid stage order, and any primitive outside the
   allowlist.
3. **Discrete-event scheduler** processes the twenty reviewed scenario actions and
   dynamically inserts detection and containment events. Ordering is a stable tuple
   of simulated time, priority, and identifier.
4. **State engine** stores only sets, roles, booleans, and numeric counters:
   compromised assets, encrypted-state flags, privilege scope, backup availability,
   signal score, containment status, and exfiltration volume.
5. **Metric engine** derives compromise/confinement time, blast radius, data impact,
   RTO/RPO, outage count, and resilience score from final state and causal events.
6. **Causal ledger** adds a sequence, previous hash, and canonical event hash to
   every record. Each profile starts a new genesis chain.
7. **Presentation layer** exports JSON, JSONL, CSV, and Markdown and exposes the
   same results through a bounded local API and static dashboard.

## Event processing

```text
load + verify bundle
        |
enqueue fixed scenario actions
        |
pop next deterministic event
        |
check containment -> network policy -> role -> asset preconditions
        |
apply state-only transition and signal score
        |
threshold reached? enqueue detection + containment
        |
snapshot state, append event, continue
        |
derive metrics, chain events, compute functional digest
```

Containment is represented as a defense event at `detection + response delay`.
Subsequent lateral movement, data-egress, impact, and recovery-inhibition actions
are marked prevented. No event is silently removed, so failed and prevented stages
remain explainable.

## Profile isolation

Profiles cannot redefine the topology or actions. They control only:

- `flat` versus `segmented` access-path policy;
- broad versus least-privileged acquired role;
- mutable versus immutable recovery state;
- detection enablement, threshold, and delays;
- backup and unrecoverable RPO intervals.

This keeps comparisons paired: all other scenario facts remain identical.

## Functional reproducibility

The functional digest commits to the engine model version, scenario, profile,
topology summary, bundle file hashes, safety assertions, metrics, complete state
snapshots, and event hash chains. It excludes only Python version and wall-clock
execution measurements.

## Runtime topology

The Python process is stateless apart from optional CLI report exports. The web
server reads packaged data and returns generated JSON; it accepts no configuration
uploads. The Docker image runs as UID/GID 65532. Compose adds a read-only root,
capability removal, `no-new-privileges`, a small no-exec temporary filesystem, and
resource caps.
