# ClawKeeper Watcher

The Watcher is the third architectural layer from the original ClawKeeper paper: an *external* LLM-driven supervisor that reasons about trajectories rather than individual commands.

## Run the daemon

```bash
# Foreground
python -m clawkeeper_core.watcher.daemon

# Or via the bundled console script (if installed)
clawkeeper-watcher

# Background
nohup python -m clawkeeper_core.watcher.daemon > watcher.log 2>&1 &
```

The daemon binds to `127.0.0.1:9099` by default. All env knobs:

| Var | Default | Purpose |
|---|---|---|
| `CK_WATCHER_HOST` | `127.0.0.1` | Bind address — DO NOT bind to `0.0.0.0` unless you intend a network-exposed Watcher (and even then, fronted by a real auth proxy) |
| `CK_WATCHER_PORT` | `9099` | |
| `CK_WATCHER_MODEL` | `gpt-5.5` | LLM the Watcher reasons with |
| `CK_WATCHER_BASE_URL` | `$OPENAI_BASE_URL` or `https://api.scode.chat/v1` | OpenAI-compatible endpoint |
| `CK_WATCHER_API_KEY` | `$OPENAI_API_KEY` | |

Health check:

```bash
curl http://127.0.0.1:9099/watcher/health
```

## Wire it into a host (Hermes)

```python
from clawkeeper_core.adapters.hermes import install
from clawkeeper_core.judge import Judge

agent = AIAgent(...)
install(Judge(), agent, watcher_url="http://127.0.0.1:9099")
```

Without `watcher_url`, the adapter falls back to the deterministic-only guard chain (still useful, just no LLM reasoning).

## What the Watcher does on each pre-tool-call event

1. Runs the deterministic guards (`exec_gate`, `path_guard`, `script_body_scan`, `url_safety`) synchronously
2. Gathers stated user intent + recent tool-call history for the session
3. Sends ONE structured prompt to the LLM containing all of the above + the proposed call
4. Parses a JSON decision: `{decision, reason, severity, signals, confidence}`
5. Applies a deterministic post-filter — hardline/critical deterministic blocks always win over the LLM's `allow`
6. Returns the final decision to the calling adapter

One LLM call evaluates the proposal. An eligible learning attempt makes an
additional synthesis call before returning; latency and model usage therefore
increase on that path. Hermes also synchronizes learned policy before its
blocking checks, using a conditional HTTP request when policy is unchanged.

## Learning and rule application

Learning is attempted only when all deterministic guards ran normally with no
findings, the final verdict is `deny` or `ask`, and its confidence is at least
0.75. Normal `None` / `block=false` returns are not findings. Nonblocking risk
findings and guard errors suppress learning. Learning failures preserve the
original evaluation decision.

Candidates need synthesis confidence of at least 0.6, a supported target, a
compilable regex, a match against the source in that target's input view, and
no matches against the built-in benign programming regression corpus. This
corpus covers common programming workflows; passing it is a regression check,
not proof that a rule cannot produce false positives on other workloads.

| Target | Learned regex searches |
|---|---|
| `exec_gate` | Normalized executable invocations and real pipelines from shared syntax analysis |
| `path_guard` | Extracted paths after home expansion and normalization |
| `script_body_scan` | The same invocation views, plus named Python operations (`python:open '/path'`), independently of the built-in marker heuristic |

Command and script patterns must match from the start of a view and cover its
complete executable/operation name. This check runs inside the same bounded
regex worker. Literal comments, assignments, print payloads, interpreter source
arguments and known metadata argument slots cannot substitute for an actual
call. Interpreter module names and script filenames remain in the view; only
inline source payloads and their positional data are masked. Nested executed
sources, including literal executable here-strings, are analyzed as separate calls. Source validation
and runtime matching use exactly the same views, including nested execution
envelopes; independent fields are never concatenated into executable source.
Incomplete command analysis is not a clean result or a learnable sample. This
remains bounded static analysis, not arbitrary Python data-flow analysis.

Learned rules are held in immutable snapshots separately from built-in rules.
Each guard chain pins one snapshot. Reload replaces the whole learned set,
including deletions, without modifying built-in policy. Startup revalidates old
records; rejected records remain in the store and are logged rather than
activated. Legacy records without source arguments use their saved command
sample; truncated historical samples that no longer match are rejected.

New rules choose a stable `subject`: `program.name`, `python.module`,
`script.path`, `python.operation` (script guard only), or `path` (path guard only).
Names/modules/operations use fullmatch; paths use search. `invocation` retains
the executable-first compatibility projection when an argv relationship is
needed. A model chooses the subject; source validation rejects an unsupported
field or a pattern that fails its source or matches the benign corpus. No
agent-specific regex format or per-call Judge is introduced.

New records retain redacted `source_texts` for compatibility plus versioned
`source_facts` containing only the selected subject's values. The fact selector
schema is 1 and `source_view_version`/validator is 5. Historical raw samples are
reparsed; normalized version-4 views retain their matching projection. Version-3
bare program samples migrate to `program.name`, preserving matches when runtime
argv contains a module/script. Ambiguous or incompatible samples are kept
inactive with `inactive_reason` rather than silently changing their meaning.
Watcher and adapters must be upgraded together: protocol 2 includes subject and
subject version in each rule and in the snapshot hash. An incompatible response
retains the last valid snapshot and pauses the current call.
An inactive historical record can be replaced atomically by a newly validated
sample with the same rule identity, without consuming an extra capacity slot.
An active duplicate is still rejected. A transient regex worker failure during
existing-record validation leaves the store intact and does not permit replacement.
Generic and nested argument fields use the same target extraction
as runtime guards. Environment variables, headers, request bodies and named
credential fields are masked before extraction. Known credential forms (including short
key/value secrets, authorization headers and URL user information) are scrubbed.
This is data minimization and heuristic redaction, not a guarantee that arbitrary
free-form text contains no sensitive data. A rule depending on a removed secret
fails source validation and is not admitted.

Legacy records are migrated atomically when read, clearing raw `source_command`
and `source_args`. Invalid records remain inspectable with their source fields
cleared. `/watcher/learned` preserves the list response and policy metadata but
returns empty/null source fields and never returns `source_texts` or `source_facts`.
Deletion accepts legacy pattern hashes (all matching targets), legacy rule IDs
retained by migration, and new target/subject/pattern rule IDs. The compatibility
subject retains its historical target-plus-pattern ID. Rules with the same regex
in different subjects have separate identities. Dashboard text is escaped before
insertion into HTML.

### Resource limits and failures

Only built-in patterns execute in-process. Learned regex compilation, source and
benign-corpus validation, and live matches run in isolated stdlib-only Python
children. Each batch has a 0.5-second wall-time budget including worker-slot
waiting, and at most four workers run concurrently. POSIX workers are created
on demand and reused, with one request per worker at a time. Timed-out, crashed
or invalid-response workers are killed and reaped; later calls create replacements.
Host exit releases workers, and forked hosts start their own pool. POSIX workers
enforce 128 MiB address-space and a one-second CPU timer reset for each request.
Windows retains the one-shot process path with wall-time/input limits.
The interpreter must be allowed to start child processes; inability to start or
complete a worker blocks the call with an error and `ask` semantics.

Limits are 128 rules, 2,048 characters per regex, 32 KiB of regex characters per
snapshot, 65,536 characters per input text, 256 texts, 128 KiB combined characters,
and 1 MiB of serialized worker input. Snapshot validation and persisted-policy
reload have five-second batch budgets (plus at most one in-flight worker).
No input is silently truncated to satisfy matching limits. Busy workers,
oversized inputs and matching errors stop the call rather than becoming an
absence of findings. The extra process boundary adds latency to learned checks.
If a validation worker is unavailable during reload, the entire reload is
aborted, the previous snapshot is retained, and health becomes degraded until a
successful reload. Malformed regex records are still rejected individually.

The store is limited to 8 MiB; admission checks prevent new records from making
it unreadable. Invalid JSON, invalid encoding, oversized or unreadable stores
remain untouched. The daemon starts with health `status=degraded`, retains its
last valid in-memory snapshot, and refuses rule synchronization with HTTP 503.
It does not publish an empty successful snapshot or a cached 304 in this state.
After repairing the file, call `POST /watcher/rules/reload` or restart the daemon.
A failed reload keeps the service degraded; a successful reload atomically
installs the recovered policy. List/delete operations on a corrupt store also
return HTTP 503 without overwriting it.

## Watcher–Hermes synchronization

Upgrade the daemon and Hermes adapter together. With `watcher_url` configured,
the adapter shares one client between its `pre_tool_call` hook and approval
callbacks. Each blocking entrypoint fetches policy before running local guards.
Observers use the latest local snapshot without additional HTTP calls. Other
adapters and standalone processes do not automatically receive these rules.

`GET /watcher/rules` returns:

```json
{
  "protocol_version": 2,
  "validation_version": 5,
  "version": "<content SHA-256>",
  "instance_id": "<process UUID>",
  "pid": 1234,
  "rules": [{"id": "<rule SHA-256>", "guard_target": "exec_gate", "pattern": "CK_EXAMPLE_\\d+", "subject": "program.name", "subject_version": 1}]
}
```

The version covers the sorted rules (including subjects) and validator version. Source samples are
excluded from this response. A matching `If-None-Match` receives `304`; both
responses include `ETag` and `X-ClawKeeper-Instance`, so a daemon restart can be
distinguished from a policy change. `/watcher/health` includes the same version
and process metadata without the rule list.

Adapters revalidate the complete response before atomically installing it.
One process supports one Watcher rule authority. A malformed response, validator
version mismatch, unavailable old daemon, or connection failure retains the
last snapshot and defers the current tool call to the operator (`ask`, mapped
to blocking by Hermes). Requests use the client's existing timeout; there is
no background polling or shared-file synchronization. Deletions reach each
adapter on its next blocking check.

Rule downloads are streamed with a 1 MiB raw-byte limit and a request budget.
The client requests identity encoding and rejects compressed snapshots before
decompression. All ordinary parsing, compilation, transport and synchronization
exceptions produce a blocking synchronization failure; the previous policy is
retained. Interrupts such as `KeyboardInterrupt` are not swallowed.

Structured records on the `clawkeeper_core.learned_rules` logger distinguish
`attempted`, `skipped`, `rejected`, `validated`, `stored`, `applied`,
`synchronized`, `sync_failed`, `failed`, and `matched`. Records include policy
version and process identity, plus rule IDs or skip reasons where applicable.
Learning records inherit session/tool context. The message itself is JSON and
the fields are also available as Python log-record attributes. A daemon's `applied` event
describes only that process; an adapter's own `synchronized` and `matched`
records provide evidence of its local policy and actual matches. The daemon
entrypoint enables INFO logging. When embedding the daemon or adapter in another
application, enable INFO on this logger to retain learning and synchronization
events.

### Replaying and testing detection

`python -m clawkeeper_core.execution 'COMMAND'` runs the real local pre-tool
guard chain and emits a decision, parsed facts and source provenance. It never
executes COMMAND, calls a model, or opens the live learning store. Use
`--event-stdin` for nested tool inputs. Export `/watcher/rules` and pass
`--rules-snapshot FILE` to reproduce an adapter's downloaded policy. Inputs and
snapshot files are capped at 1 MiB; parsed code shares the normal source/node/
depth budgets. Recognized secrets in debug evidence are masked without moving
source byte ranges.

Run `pytest -q tests/test_command_facts.py tests/test_command_properties.py
tests/test_semantic_learning.py tests/test_watcher_sync.py` for the focused
suite. These cover field selection, source provenance, quote/wrapper
transformations, descriptor order, uncertainty outcomes, old-view migrations,
subject-aware identities, pinned snapshots, and real separate-process learning,
restart, deletion and disconnect behavior. Dangerous inputs remain inert strings;
only fixed printf scripts run as benign differential probes.

## Design notes

- **The LLM proposes, the post-filter disposes.** See `policy.py`. The Watcher's LLM cannot accidentally weaken the hardline floor — if any deterministic guard says critical-block, the LLM's verdict is overridden.
- **Fail-safe default is `ask`.** When the daemon is unreachable, or the LLM output is unparseable, the client returns `ask` (defer to operator) rather than silently allowing.
- **Per-session trajectory memory; persistent learned rules.** Call histories remain session-local; validated rules persist across sessions and daemon restarts.
- **No multi-step tool-loop.** v1 gathers data eagerly and makes one evaluation call, with a separate synthesis call when eligible for learning.
