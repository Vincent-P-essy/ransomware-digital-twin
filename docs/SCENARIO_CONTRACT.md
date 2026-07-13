# Safe scenario contract

## Closed action schema

Every action has exactly these fields:

```json
{
  "id": "reviewable-identifier",
  "at_seconds": 35,
  "stage": "lateral-movement",
  "primitive": "lateral_move",
  "source_asset": null,
  "target_asset": null,
  "path_id": "finance-peer",
  "volume_gb": 0,
  "signal_score": 2
}
```

Unknown fields fail validation. There is no field for a command, executable,
argument vector, script, payload, URL, address, file path, or code fragment.

## Primitive allowlist

| Primitive | State effect |
|---|---|
| `initial_access` | Add one reviewed asset identifier to the compromised set |
| `credential_access` | Set modeled role to `user` or `admin` according to profile |
| `lateral_move` | Evaluate one reviewed topology path and possibly add its target |
| `exfiltration_attempt` | Increment a bounded numeric counter |
| `encrypt_impacted_assets` | Add compromised/encryptable IDs to a state set |
| `destroy_recovery_points` | Toggle backup availability unless immutable |

Primitive-specific source/target/path/volume shapes are enforced. The encryption
selector must be the literal `compromised-assets`; it is never interpreted as a
filesystem expression.

## Stage order

Actions must be sorted by time and identifier and can only progress through:

```text
initial-access -> credential-access -> lateral-movement
-> exfiltration -> impact -> recovery-inhibition
```

Defense events are generated internally and cannot be supplied by the scenario.

## Review requirements

Any topology, profile, or scenario change requires updating its integrity hash,
rerunning the complete test suite, reviewing metric deltas, and explicitly
regenerating the golden evidence. A changed functional digest is expected to be
visible during review.
