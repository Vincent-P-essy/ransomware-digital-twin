# Experimental methodology

## Design

The experiment is a deterministic paired control ablation. Every profile receives
the same topology, access paths, action order, simulated timestamps, volumes, and
signals. Only declared defensive controls change.

The five profiles are:

1. flat/broad privilege/mutable backup/no response baseline;
2. segmentation only;
3. least privilege only;
4. immutable backup only;
5. segmentation + least privilege + immutable backup + detection-response.

This design exposes mechanism rather than merely comparing two opaque bundles.

## Scenario time

`at_seconds` is a logical incident clock. The scheduler never sleeps. Detection is
scheduled at `threshold-crossing time + sensor delay`; containment is scheduled at
`detection time + response delay`. The layered profile crosses its threshold at 35
seconds, detects at 39 seconds, and contains at 47 seconds.

Logical time is deterministic. Wall-clock runtime is recorded separately and has
no incident interpretation.

## Ground truth

Ground truth is the reviewed state-machine contract, not a claim about adversary
probability. An access path succeeds only when:

- its source asset is already compromised;
- containment has not taken effect;
- the profile's network policy permits the path;
- acquired role rank meets the path requirement;
- the target is not already compromised.

The three role ranks are `user < service < admin`. The segmented profile permits
only paths explicitly marked `segmented_allowed`.

## Data impact

Primary data is the sum of assets classified `primary` (291 GB in this model).

```text
encrypted primary data = sum(data_gb for encrypted primary assets)
irrecoverable data      = encrypted primary data if recovery points unavailable, else 0
data lost %             = irrecoverable data / all primary data * 100
```

Exfiltration is a counter bounded by the target asset's modeled data volume. It
does not read or transmit bytes.

## Blast radius

```text
raw blast radius      = compromised systems / all systems * 100
weighted blast radius = sum(criticality of compromised systems)
                        / sum(criticality of all systems) * 100
```

Criticality ranges from 1 to 5 and is declared in the topology.

## RTO and RPO model

When impact flags exist, RTO is:

```text
max(per-asset restore time if backups usable, otherwise rebuild time)
+ 30 minutes coordination
+ 5 minutes per impacted system
```

When automated containment prevents impact, RTO is a forensic/recovery allowance
of `30 + 4 minutes per compromised endpoint`. RPO is zero without encrypted
primary data; otherwise it is the backup interval when recovery points survive or
the declared unrecoverable window when they do not.

These are transparent heuristics for comparison, not business continuity promises.

## Resilience score

The illustrative 0–100 score subtracts weighted penalties:

- 35% weighted blast radius;
- 35% data-loss percentage;
- 15% exfiltration as a percentage of primary data;
- 15% RTO normalized to 1,000 minutes and capped at 100%.

The raw metrics remain authoritative; the composite score exists only for ranking
within this experiment.

## Reproducibility

- all input bytes are hash-pinned;
- identifiers, stage order, primitive shapes, and graph references are validated;
- event ordering and canonical JSON are stable;
- every event includes a full state snapshot and hash-chain link;
- the golden manifest pins all exports;
- CI executes the comparison twice and reproduces the functional digest;
- environment-dependent wall-clock measurements are excluded from equality gates.
