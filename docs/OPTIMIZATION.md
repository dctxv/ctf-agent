# Policy proposals (M8 - offline, human-gated)

> **HUMAN APPROVAL REQUIRED.** These are recommendations derived from past evaluation
> data. Nothing here is applied automatically - no config or code is changed. A human
> reviews each one and only then deploys. The inputs are outcome and cost metadata only
> (no flags, keys, or evidence), so held-out solutions never enter this loop.

Scope: dataset=test

Contamination check: clean (no answer material in inputs)

## Default policy: 'economy'  `[advisable]`

- **Recommendation:** Adopt config 'economy' as the default.
- **Evidence:** Best verified success (6/6) at the lowest cost ($0.0027) among 10 compared configs.
- **Rationale:** No compared config does better; several match it for more money.

## Avoid 'agent-full' as configured  `[advisable]`

- **Recommendation:** Do not use 'agent-full' by default.
- **Evidence:** Same verified success as 'economy' (6/6) at 1.22x the cost ($0.0033 vs $0.0027).
- **Rationale:** Pure cost with no measured benefit on this set.

## Avoid 'balanced' as configured  `[advisable]`

- **Recommendation:** Do not use 'balanced' by default.
- **Evidence:** Same verified success as 'economy' (6/6) at 1.59x the cost ($0.0043 vs $0.0027).
- **Rationale:** Pure cost with no measured benefit on this set.

## Avoid 'flash-baseline' as configured  `[advisable]`

- **Recommendation:** Do not use 'flash-baseline' by default.
- **Evidence:** Same verified success as 'economy' (19/19) at 1.22x the cost ($0.0033 vs $0.0027).
- **Rationale:** Pure cost with no measured benefit on this set.

## Avoid 'flash-memory' as configured  `[advisable]`

- **Recommendation:** Do not use 'flash-memory' by default.
- **Evidence:** Same verified success as 'economy' (9/9) at 1.22x the cost ($0.0033 vs $0.0027).
- **Rationale:** Pure cost with no measured benefit on this set.

## Avoid 'maximum' as configured  `[advisable]`

- **Recommendation:** Do not use 'maximum' by default.
- **Evidence:** Same verified success as 'economy' (6/6) at 3.33x the cost ($0.009 vs $0.0027).
- **Rationale:** Pure cost with no measured benefit on this set.

## Avoid 'multi-agent' as configured  `[advisable]`

- **Recommendation:** Do not use 'multi-agent' by default.
- **Evidence:** Same verified success as 'economy' (7/7) at 1.52x the cost ($0.0041 vs $0.0027).
- **Rationale:** Pure cost with no measured benefit on this set.

## Avoid 'single-agent' as configured  `[advisable]`

- **Recommendation:** Do not use 'single-agent' by default.
- **Evidence:** Same verified success as 'economy' (7/7) at 1.11x the cost ($0.003 vs $0.0027).
- **Rationale:** Pure cost with no measured benefit on this set.

## 'agent-1step': capability/cost trade-off  `[needs-review]`

- **Recommendation:** Use 'agent-1step' only if its lower cost justifies the lower success.
- **Evidence:** 0/6 (0%) at $0.0008, vs 'economy' 100% at $0.0027.
- **Rationale:** Lower verified success; whether the saving is worth it is a human call.

## 'raw-model': capability/cost trade-off  `[needs-review]`

- **Recommendation:** Use 'raw-model' only if its lower cost justifies the lower success.
- **Evidence:** 5/6 (83%) at $0.0029, vs 'economy' 100% at $0.0027.
- **Rationale:** Lower verified success; whether the saving is worth it is a human call.

