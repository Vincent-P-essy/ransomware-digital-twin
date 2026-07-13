# Limitations and honest claims

## What the project demonstrates

- a reviewed enterprise graph spanning identity, endpoints, services, data,
  security, and recovery;
- safe deterministic incident and response state transitions;
- paired control ablation for segmentation, privilege, backup, and response;
- explicit operational metrics and causal evidence;
- integrity-pinned inputs and reproducible golden outputs;
- CLI, bounded API, dashboard, hardened container, CI, and failure tests.

## What it does not demonstrate

- **No malware or attack execution.** There are no commands, process launches,
  protocol clients, encryption algorithms, credential operations, or live targets.
- **No protocol realism.** Identity, network, backup, and endpoint behavior are
  graph policies rather than implementations of directory services, SMB, EDR, or
  orchestration platforms.
- **No adversary probability model.** Access-path success is deterministic when
  declared preconditions hold.
- **No production detection benchmark.** Signal values and delays are scenario
  assumptions, not measurements from a real SOC.
- **No statistically calibrated loss estimate.** Data loss is a transparent binary
  recoverability model. Exfiltration is a counter.
- **No authoritative RTO/RPO.** Recovery values are illustrative formulas over
  declared restore/rebuild times and omit staffing, dependencies, vendor delays,
  legal response, and infrastructure contention.
- **No complete enterprise.** Sixteen systems and fourteen paths are deliberately
  small enough for review and reproducibility.
- **No claim that one control is sufficient.** Ablations isolate modeled effects;
  the layered result depends on all declared assumptions.
- **No production web service.** The API has no authentication, TLS, tenancy,
  database, queue, or distributed resource management.

## Appropriate interpretation

Use results to explain mechanisms, compare transparent assumptions, teach
resilience reasoning, and test reporting pipelines. Do not use the numeric score or
timings as a forecast, insurance input, compliance attestation, or authorization to
change production controls.

## Production-oriented extensions

Useful next steps include importing sanitized CMDB/dependency data, independent
control calibration, uncertainty ranges, Monte Carlo sensitivity analysis,
capacity-aware recovery scheduling, signed experiment attestations, and explicit
review workflows. Any real integration should remain read-only and outside the
state-only simulator process.
