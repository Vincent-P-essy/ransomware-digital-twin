# Contributing

Changes must preserve the state-only safety boundary and make changed assumptions
reviewable.

1. Keep scenarios inside the six allowlisted primitives.
2. Do not add command, script, executable, payload, URL, or target-address fields.
3. Update the bundle hash for every changed topology, scenario, or profile file.
4. Add positive and negative tests for contract or behavior changes.
5. Explain metric changes and limitations in the review description.
6. Regenerate golden evidence intentionally and verify its functional digest.
7. Run `make test` and `make quality`.

Do not add real secrets, production telemetry, executable samples, process
execution, destructive filesystem calls, outbound runtime clients, or hidden
external effects.
