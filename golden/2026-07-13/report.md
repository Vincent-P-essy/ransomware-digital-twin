# Enterprise ransomware resilience comparison

- Scenario: `meridian-ransomware-state-machine`
- Functional SHA-256: `7f7897150704ccce3bd80ffc0492f2ab309eac5b4dc3143489831d57077ac30d`
- Baseline: `flat-baseline`
- Highest resilience score: `resilient-reference`

| Profile | Touched | Encrypted | Confinement | Exfiltrated | Data lost | RTO | RPO | Blast radius | Score |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `flat-baseline` | 15/16 | 15 | n/a | 100.0 GB | 100.0% | 825 min | 480 min | 93.8% | 15.4 |
| `segmented-only` | 2/16 | 2 | n/a | 0.0 GB | 0.0% | 50 min | 60 min | 12.5% | 96.9 |
| `least-privilege-only` | 3/16 | 3 | n/a | 40.0 GB | 0.0% | 105 min | 60 min | 18.8% | 91.6 |
| `immutable-backup-only` | 15/16 | 15 | n/a | 100.0 GB | 0.0% | 195 min | 15 min | 93.8% | 59.9 |
| `resilient-reference` | 2/16 | 0 | 47 s | 0.0 GB | 0.0% | 38 min | 0 min | 12.5% | 97.1 |

All actions are deterministic in-memory state transitions. No host file is encrypted, no payload is executed, and no data leaves the process.

Timings in the metrics are simulated incident time. Wall-clock execution measurements are environment-dependent and excluded from the functional digest.
