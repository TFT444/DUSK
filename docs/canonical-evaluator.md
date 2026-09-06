# Canonical evaluation boundary

The framework-neutral evaluator in `dusk.application` is the application-layer
boundary shared by the frozen Gate API and the production control plane. It
coordinates a decision while keeping authentication, time, trace generation,
semantic enrichment, behavioural analysis, policy evaluation, offense memory,
decision persistence, and delivery behind explicit ports.

## Trust and effect boundaries

The HTTP adapter authenticates a caller before constructing an
`EvaluationPrincipal`; tenant and principal identifiers are trusted adapter
output, not action fields. The evaluator authorizes that principal before it
reads history or invokes analysis. The policy port receives only the trusted
principal, normalized action view, and behavioural result.

`DecisionWrite`, `OffenseWrite`, and `DeliveryIntent` describe effects without
binding orchestration to Flask, FastAPI, PostgreSQL, a message broker, or a
semantic-enrichment provider. A delivery intent is a request for delivery and
is never evidence that a downstream action executed.

| Mode | Read offense history | Read similar decisions | Write offense | Persist decision | Publish delivery |
| --- | --- | --- | --- | --- | --- |
| `active` | Yes | Yes | On refusal | Yes | Yes |
| `shadow` | No | No | No | No | No |

Shadow evaluation still returns the computed decision and delivery intents for
comparison, but adapters receive no state-changing or external call. This
prevents shadow traffic from contaminating behavioral memory or triggering
webhooks, broker actions, or persistence.

## Legacy compatibility

The Flask `/v1/gate` route remains responsible for its existing request parsing,
authentication, status codes, and JSON serialization. Its adapters preserve the
established scoring, rounding, watch/enforce behavior, SIE fallback, offense
memory ordering, trace generation, decision history, and webhook sequence.
Golden contract tests protect those observable behaviors.

The example remains self-contained by carrying a byte-identical copy of the
canonical evaluator. A source-parity test prevents drift until the example can
consume a released DUSK package artifact.

## Migration and rollback

This change introduces no schema migration and exposes no new route. Production
`/v2` activation remains disabled by default through the control-plane feature
flag. A rollback restores the legacy Flask orchestration; stored data and the
frozen `/v1/gate` contract require no rollback operation.

Future policy and durable persistence work must implement the existing ports
rather than add framework dependencies to the evaluator. Changes to the v1
adapters require golden parity evidence before release.
