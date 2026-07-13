# Safety case

## Claim

Running the packaged scenario cannot execute offensive behavior because the
runtime exposes only typed in-memory state transitions and report output.

## Evidence

| Safety property | Design evidence | Automated evidence |
|---|---|---|
| No arbitrary execution | Closed enum and fixed action fields | Unknown primitive/extra-field negative tests |
| No process execution | Runtime has no subprocess or shell surface | AST source gate |
| No host-file encryption | Impact changes a set of asset IDs only | Safety assertions and state tests |
| No data exfiltration | Egress is a bounded float counter | Runtime egress-import gate |
| No destructive file operations | No delete/rename/unlink calls | AST destructive-call gate |
| No nondeterministic scenario | No random, sleep, live time, or UUID generation | Determinism gate and AST gate |
| No unreviewed target | Asset/path IDs must resolve in pinned topology | Dangling-reference validation |
| No bundle substitution | Every input file has a pinned SHA-256 | Mutation and golden integrity tests |
| No hidden partial result | Validation completes before simulation | CLI/API structured failure tests |

The only filesystem writes are user-directed report exports from the CLI. They
contain JSON, JSONL, CSV, or Markdown evidence and never modify modeled target
files.

## Runtime boundary

The local web API accepts only existing profile identifiers. It cannot receive a
new scenario or topology. The server defaults to loopback and has no authentication
or TLS; the hardened Compose configuration must not be replaced with an untrusted
public bind.

## Residual safety considerations

- Python and the container runtime remain general-purpose software; normal host
  patching and isolation practices still apply.
- A maintainer can modify source code. Review plus the safety gate is the control;
  the project is not a formally verified capability system.
- Report output paths are selected by the local operator and should not point to
  sensitive locations.
