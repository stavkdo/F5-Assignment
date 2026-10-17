# API Traffic Log Redactor

A command-line tool (and HTTP service) that reads API traffic logs as NDJSON (one HTTP transaction per line),
redacts sensitive data (credentials, tokens, emails, card numbers, personal data) according to
rules in a YAML file, and writes the same NDJSON with the secrets replaced. It streams, so the
input can be far larger than memory, and it never crashes on a bad line.

The whole development process, phase by phase with the questions and decisions along the way,
is in [`docs/development-process.html`](docs/development-process.html). GitHub shows HTML as
source, so download it and open it in a browser.

## Why Python

I wrote this in Python because it's the language I know best, and so I could explain the code.
I don't know Go but I'm willing to learn.

| Dependency | Why |
|---|---|
| PyYAML | The rules are YAML, and the standard library has no YAML parser. Loaded with `safe_load`, which can't build arbitrary objects. |
| FastAPI + uvicorn | Service mode only: uvicorn is the HTTP server, FastAPI does routing and the streamed response. The CLI never imports them. |
| pytest, httpx (dev only) | Test runner, and the HTTP client FastAPI's `TestClient` needs. |

Everything else (JSON, regex, hashing, URL decoding) is the standard library. Runtime
dependencies are pinned exactly in `pyproject.toml`, so the Docker image is built from the
versions the tests ran against.

## Build, run and test

Python 3.11 or newer.

```sh
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"            # installs the dependencies, pytest and the `redactor` command
```

### CLI

```sh
redactor [--rules rules.yaml] [--max-line-bytes N] [input-file]   # reads stdin if no file is given

redactor --rules rules.yaml input.ndjson > redacted.ndjson
cat input.ndjson | redactor > redacted.ndjson
python -m redactor input.ndjson    # same thing without installing
```

- **stdout:** the redacted NDJSON, one line per input line (blank lines are skipped).
- **stderr:** one line per problem (`redactor: line 20: invalid JSON`), then a summary:

```text
redactor: 50 lines read: 43 redacted, 5 replaced by an error record, 2 blank skipped
  errors: invalid JSON 3, not a JSON object 2
  redactions per rule:
    auth-headers        9
    ...
```

- **Exit codes:** `0` done (bad lines are reported, not fatal), `2` the rules or the input file
  can't be read, `1` an I/O error while streaming, `130` Ctrl-C.

### Bonus flags: HMAC hashing and live rule reload

```sh
# HMAC: hash with a secret key instead of plain SHA-256 (see "Hashing" below)
export REDACTOR_HMAC_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
redactor --hmac input.ndjson          # PowerShell: $env:REDACTOR_HMAC_KEY = "..."

# Hot reload: edit rules.yaml while a long stream runs; new lines use the new rules
tail -f app.log | redactor --watch-rules > redacted.log
```

Without `--hmac` the tool hashes with plain SHA-256, as the brief defines. With `--hmac` but no
key (or one shorter than 32 bytes), it refuses to start (exit code `2`): it never quietly falls
back to the weaker hash.

### Service mode

```sh
redactor --serve --addr :8080 --rules rules.yaml
curl -s -X POST --data-binary @input.ndjson http://localhost:8080/redact > redacted.ndjson
curl -s -T - -H "Transfer-Encoding: chunked" http://localhost:8080/redact < input.ndjson   # streamed upload
curl -s http://localhost:8080/healthz     # {"status":"ok"}
```

- `POST /redact`: NDJSON in, exactly the lines the CLI would write out (`200`,
  `application/x-ndjson`), streamed in both directions.
- `GET /healthz`: `200 {"status":"ok"}` (see [Health endpoint](#health-endpoint)).
- If the rules can't be loaded, the process exits with code `2` **before opening the port**, so
  it never accepts traffic it can't redact.

With Docker (the rules are mounted, not built in):

```sh
docker build -t redactor:0.1.0 .
docker run -p 8080:8080 -v "$PWD/rules.yaml:/etc/redactor/rules.yaml:ro" redactor:0.1.0
```

### Tests

```sh
python -m pytest            # all tests
python -m pytest -rx        # also list the known gaps (expected failures) and why
```

| Area | Files |
|---|---|
| Rules and redaction | `test_rules` (every invalid config is rejected), `test_actions`, `test_engine`, `test_key_matching`, `test_value_rules`, `test_body_shapes` |
| Robustness | `test_failures` (bad lines, deep nesting, invalid UTF-8), `test_streaming` (flat memory, huge lines), `test_jsonio` |
| End to end | `test_fixtures` (golden files), `test_idempotency`, `test_cli`, `test_service` (including a real server streaming both ways) |
| Deployment | `test_deploy`: the ConfigMap equals `rules.yaml`, the mount path, probes, ports, image tag, non-root |
| Bonuses | `test_hmac` (key handling, no plain SHA-256 left, the key never printed), `test_reload` (valid, broken, deleted and unchanged rule files, a live CLI stream) |
| Known gaps | `test_known_gaps`: strict expected failures (see [Known limitations](#known-limitations)) |

## Project layout

```text
rules.yaml            the redaction rules (config, not code)
redactor/
  rules.py            YAML -> validated rule objects, regexes compiled once
  actions.py          mask / partial / hash / remove and the luhn validator: small pure functions
  jsonio.py           JSON read/write that keeps numbers, repeated keys and odd characters intact
  engine.py           Redactor: one line in, one redacted line out. Knows nothing about files
  stream.py           line-by-line driver: line size limit, error records, summary
  reload.py           --watch-rules: re-reads the rules file during a stream, swaps only valid rules
  service.py          HTTP service: POST /redact (streamed), GET /healthz
  cli.py              argument parsing, exit codes, starts the service with --serve
tests/                pytest suite and golden fixtures
Dockerfile            the service image
deploy/               configmap.yaml, deployment.yaml, service.yaml
docs/                 development-process.html: the development process, phase by phase
```

## Design decisions and trade-offs

### What the engine reads: "headers" and "body"

In the transaction and in its `response`, the `headers` field is walked with the **headers**
scope and **every other field** (`body`, `path`, fields I don't know about) with the **body**
scope. An unexpected field like `"query": {"password": ...}` is still
redacted. Anything decoded out of a string (embedded JSON, a form, a query) is payload, so it
uses the body scope.

### Rule order and overlaps

1. For each key, the **first matching key rule** wins and its action applies to the whole value.
   Value rules don't run on that value, so one secret is never counted twice.
2. Otherwise every string goes through **all value rules in config order**.

Order matters where patterns overlap: `jwt` runs before `credit-card`, so digits inside a token
aren't taken for a card, and `email` writes a hash with no `@`, so later rules can't match in it.

### Recursion

The walker is a recursive function over the JSON tree: objects get key rules and then recurse,
arrays recurse, strings are decoded or go through the value rules, and other values are kept.
The recursion mirrors the data's shape, so the code is short and easy to check. Its weakness is
the call stack: a hostile `[[[[...]]]]` 5000 levels deep used to crash with `RecursionError`.
Now there's an explicit limit of **100 levels** (real traffic rarely passes ~20), and a deeper
line becomes an error record. An explicit stack would remove the limit, but it makes the code
harder to read for a case no real log has.

### Decoding nested encodings, and why it stops at 3

A string can hide another format inside it. Sample line 1's response `body` is the *string*
`"{\"token\":\"...\"}"`: to the JSON parser it's just text, so the `token` key inside would never
be seen. So before redacting a string, the engine checks what it contains, peels off one layer,
and redacts what's inside:

| The string is... | Example in → out |
|---|---|
| JSON (starts with `{`, `[` or `"` and parses) | `{"password": "hunter2"}` → `{"password":"****"}` |
| A URL with a query | `/v1/reset?token=abc123&lang=en` → `/v1/reset?token=****&lang=en` |
| A form (`name=value&name=value`) | `email=bob%40example.com&password=hunter2` → `email=sha256:…&password=****` |
| Anything else: free text | `login failed, password=hunter2` → `login failed, password=****` |

Only what was redacted changes. If nothing inside is secret, the original string is kept exactly,
spaces included. In free text a key rule applies whatever its scope: `Authorization: Bearer ...`
pasted into a body is still a credential.

**Why only these formats.** Each one is easy to recognise, and decoding then re-encoding it gives
back the same text, so the output doesn't change where nothing was secret. base64 isn't decoded:
almost any word is valid base64, so it would "find" encodings everywhere. gzip isn't either: a
small gzip can expand to gigabytes (a decompression bomb).

**Why stop at 3 levels.** Real logs nest one or two levels (JSON inside a log record, maybe JSON
inside a form field); anything deeper is most likely made on purpose. Past the limit the line
**fails closed** and becomes an error record. It can't fall back to free text: each level escapes
the quotes of the one inside, so at level 4 there are 15 backslashes between `password` and its
value, and the free-text scan wouldn't recognise the key.

### Streaming

Input is read as **bytes, one line at a time**. Each line is parsed fully, redacted, written,
and dropped before the next is read. A line is a small self-contained unit, so a full parse per
line is simpler than a streaming JSON tokenizer. `--max-line-bytes` (default 1 MiB) caps one
line: a longer one is read in chunks and thrown away, never held in memory, and replaced by a
`line too long` error record.

**Complexity**, for *B* input bytes, *V* value rules and a longest line of *L* bytes:

- **Time: O(B × V)**, each string scanned once per value rule, but only if **every regex runs in
  linear time**, which Python's `re` doesn't guarantee.
- **Memory: O(L)**, independent of the input size.

### Rule matching

- Every regex is **compiled once** when the rules load.
- `exact` key names are **case-insensitive** (like HTTP headers). `regex` key rules are
  **anchored**, so `password_hint` and `tokenizer` don't match.
- The `luhn` validator rejects about 90% of random 16-digit numbers, so order references and
  timestamps survive. It counts every Unicode digit, like `\d` does, so a card in full-width
  digits (`４１１１…`) is masked too.
- **Config errors fail at startup** (unknown action, bad regex, duplicate names, ...): exit code
  `2` before reading a line.

### Changes to rules.yaml

The brief allows changing the config with a reason. All changes are in `rules.yaml`, none in code:

| Change | Why |
|---|---|
| `credit-card` also matches cards printed in groups (4-4-4-4, 4-6-5 Amex, 4-6-4 Diners), with spaces or dashes | `\b\d{13,19}\b` missed `4111 1111 1111 1111` (sample lines 1, 6, 36, 44). The pattern lists real layouts: a loose "digits with separators" pattern would start at a stray digit, fail Luhn, and let the real card leak. |
| `pii-fields` key rule: `ssn`, `phone`, `dob` and similar names | Sample line 37. A field *named* `phone` is a phone number, so there are almost no false positives. |
| `url-credentials` value rule, before `email` | `postgres://admin:hunter2@db:5432/app` leaked. Now `postgres://****@db:5432/app`. |
| `email` gets a lookbehind | Same matches, linear instead of quadratic time. |
| `jwt`: base64url alphabet, lookbehind, possessive quantifiers | The user report. See [The JWT report](#the-jwt-report). |

SSN and phone **value** rules weren't added: the brief's minimum doesn't list them, and they
have real false-positive costs (see [What I'd do with more time](#what-id-do-with-more-time)).

### Numbers and non-string values

Value rules also read **integers**: `"amount": 4111111111111111` is still a card, so it becomes
`"************1111"`, a string. The cost: Luhn passes about 10% of random numbers, so a 13–19
digit ID can be redacted like a card. I chose leak safety over type stability.

Under a sensitive key, strings and numbers get the action, `null` and booleans are kept, and in
an array or object every scalar inside gets the action, so the shape is kept (`["****", "****"]`).

### Failure handling

A line that can't be processed (invalid JSON, not an object, nested deeper than 100 levels, too
long) is replaced on stdout by an **error record** and reported on stderr:

```text
stdout:  {"redactor_error":{"line":20,"reason":"invalid JSON"}}
stderr:  redactor: line 20: invalid JSON
```

Why an error record: passing the line through could leak secrets, and dropping it silently would
hide that data is missing. The record contains nothing from the input, says which line failed and
why, and keeps the output valid NDJSON.

The reason is always one of a **fixed set of strings**, never `str(exception)`, because Python's
error messages can quote the input. An unexpected exception in one line becomes an
`internal error` record, and the stream goes on.

**Rules are all or nothing, checked before anything runs.** The brief says the service must not
pass traffic unredacted if the rules can't be loaded. So any problem exits with code `2` before
the CLI reads a line or the service opens its port. "Can't be loaded" includes a file that
parses but has **no rules**, or a **misspelled section** (`key_rule:`): both would start a
redactor that redacts nothing. One bad rule rejects the whole file.

Blank lines are skipped and counted. Invalid UTF-8 is replaced with U+FFFD and the line is still
redacted. `NaN` and `Infinity` are rejected as invalid JSON.

### Service mode: streaming both ways

`POST /redact` never holds the whole body. uvicorn hands it over in chunks, `split_lines` cuts
them into lines with the same 1 MiB limit as the CLI, and each line is redacted and sent back
right away. If the client reads slowly, we stop reading its body, and TCP flow control does the
rest. A test sends one line, waits for its redacted copy, and only then sends the next.

- **The redaction runs in a worker thread** (`asyncio.to_thread`). Every request shares one event
  loop, so CPU work on the loop would freeze every other request and `/healthz`. Measured with 4
  clients sending 1 MB lines: `/healthz` took up to **2.5 s** with the work on the loop, under
  **0.15 s** in a thread.
- **One `Redactor` per request**, since it holds per-line counts. The compiled rules are shared.
- **The status is always `200`.** It's sent before line 2 is read; bad lines become error records.

### Idempotency

`redact(redact(x)) == redact(x)`, tested over the whole sample file. `hash` alone wasn't stable,
since hashing a hash gives a new value. Hash output is now written as `sha256:<64 hex>` (or
`hmac-sha256:<64 hex>` with `--hmac`), and a hash rule leaves a value alone if it is already a
hash or a mask.

### Hashing: is SHA-256 safe?

The brief and `rules.yaml` say SHA-256, so that's the default. But plain SHA-256 can be
*guessed forwards*: anyone can hash `bob@example.com` and look for the result in the logs. A
card has only about 10⁵ unknown candidates once the bank prefix, the last 4 digits and the Luhn
digit are known, a fraction of a second to try them all.

**`--hmac` (bonus)** fixes that with **HMAC-SHA256**: a hash that mixes in a secret key. The same
value still gives the same output, so you can still see that two lines belong to the same user,
but without the key nobody can hash a guess and compare. The key:

- comes from the environment variable `REDACTOR_HMAC_KEY`, never from `rules.yaml` (it's in git)
  or the command line (shell history and `ps` would show it);
- must be at least 32 bytes (as long as the hash itself), or the tool refuses to start;
- is never printed: not in errors, and not in the settings' `repr`.

**In Kubernetes** (not wired up here), it would take three small changes. First, a **Secret**
holding the key: a Secret is like a ConfigMap, but meant for passwords and keys, kept out of git,
and access to it can be limited. Second, an environment variable in `deployment.yaml` filled from
that Secret (`valueFrom: secretKeyRef`). Third, `--hmac` added to the container's args. The cost
of HMAC: if the key is ever changed, new hashes no longer match old ones.

### Hot reload of the rules (bonus, CLI)

`--watch-rules` is for long-running streams, like `tail -f app.log | redactor --watch-rules`.
Stopping the stream to change a rule would mean restarting where you left off, so instead:

- Before each line, at most every 2 seconds, the tool reads the rules file again.
- If the content changed and the **new rules are valid**, they're used from the next line on. A
  line is never redacted half with the old rules and half with the new ones.
- If the new rules are **invalid** (broken YAML, no rules, an unknown action) or the file is
  gone, the tool **keeps the old rules** and writes a warning to stderr, once. It never runs with
  no rules, the same "fail closed" as at startup.
- In this mode every output line is flushed right away, so a reader sees it at once.

The check runs when a line arrives, so an idle stream costs nothing, and new rules are always
in place before the next line is redacted.

**Why only the CLI.** In Kubernetes, the service reads its rules once at startup, and a change
needs `kubectl rollout restart`. Kubernetes does update the file of a mounted ConfigMap inside a
running pod by itself (within about a minute), so the same watcher could run in the service as a
background task. I kept it to the CLI for now: in the service, a failed reload would also need to
be visible from outside (in `/healthz` or a metric), which is more to design and test.

### Output format and `jsonio.py`

A redactor should change the secrets and nothing else. The output keeps key order, every number
exactly as written (`10.50`, `1e3`), and repeated keys; only whitespace is removed. Python's
`json` can't do that: a round trip rewrites `10.50` as `10.5` and `1e3` as `1000.0`, keeps only
the last of a repeated key, and accepts `NaN`, which isn't JSON.

`jsonio.py` isn't a parser of its own. It uses the standard library's C decoder with hooks, plus
a writer of about 30 lines. I checked `orjson`, `ujson`, `rapidjson` and `simplejson` first, and
none keeps all of this. The cost is about 17% of the time per line, because the writer is pure
Python. The complexity is the same. I kept it, because a log that changed in places that weren't
secrets is harder to trust.

## The JWT report

> Users reported that the provided `rules.yaml` misses some JWTs seen in production samples.

as we can see in the lines (output of the provided rules):

```
11 - {"ts":"2025-01-15T10:00:10Z","method":"POST","path":"/oauth/token","headers":{},"body":{"grant_type":"password"},"response":{"status":200,"headers":{"Content-Type":"application/json"},"body":"{\"access_token\":\"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiPz8_In0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk\",\"expires_in\":3600}"}}

15 - {"ts":"2025-01-15T10:00:14Z","method":"POST","path":"/v1/sso","headers":{},"body":{"id_token":"****_adQssw5c","note":"forwarded header was Bearer ****_adQssw5c"},"response":{"status":200,"headers":{},"body":null}}

16 - {"ts":"2025-01-15T10:00:15Z","method":"POST","path":"/v1/session/refresh","headers":{},"body":{"msg":"session eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiPz8_In0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk expired, retry"},"response":{"status":401,"headers":{},"body":null}}
```

there is a problem with the JWT rule, the regex doesnt cover the whole JWT cases and causes leaks.
To fix that we need to change the rule of the JWT to include all of the possible options.

Lines 11 and 16 leak the **whole** token, and line 15 leaks the end of its signature. The
per-rule summary showed it too: `jwt 2`, both on line 15.

### Root cause: two bugs in one pattern

```yaml
pattern: 'eyJ[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]*'
```

**1. Wrong alphabet (the leak).** A JWT is three **base64url** parts joined by dots (RFC 7515):
`A-Z a-z 0-9 - _`, no `=` padding. `[A-Za-z0-9+/=]` is plain base64, so the match stops at the
first `-` or `_`, and most real tokens have one. In the **signature** (line 15) the match just
ends early and the tail leaks. In the **payload** (lines 11 and 16) the `\.` after it can't
match, so nothing is masked at all.

**2. Quadratic time.** On `eyJeyJeyJ…`, `re` retries from every `eyJ` and scans to the end each
time. 60 KB took 2.3 s, and fixing the alphabet alone
didn't change that.

### The fix (only `rules.yaml` changed)

```yaml
pattern: '(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]++\.[A-Za-z0-9_-]++\.[A-Za-z0-9_-]*+'
```

| Part | Why |
|---|---|
| `[A-Za-z0-9_-]` | The base64url alphabet, from the spec. Keeping `+/=` "to be safe" broke `token=eyJ…`, because the lookbehind then saw `=` as part of the token. |
| `(?<![A-Za-z0-9_-])` | A token may only start where a run starts, so on `eyJeyJ…` only the first `eyJ` is tried. |
| `++` (possessive) | Characters are never given back, so a failed attempt costs one pass. |
| `*+` on the last part | An unsigned token (`alg: none`) has an empty signature. |


### Why not a detector in code instead of a regex

A Python function could decode the header and check for an `alg` field. I kept the regex:

- **Rules are config.** The report is about `rules.yaml`, and a code detector would be the one
  rule nobody can read or change there.
- **A miss is worse than a false mask.** The decode check would reject a token cut short by
  an upstream logger, and that's a leak. Text shaped like `eyJ….….…` is almost always a JWT
  anyway (`eyJ` is `{"` in base64).
- **No speed gain.** Both are one linear pass.

### The trade-off: a JWT glued to a word isn't matched

A *run* is a stretch of characters that could all belong to a token: letters, digits, `-` and
`_`. It ends at a space, a quote, `.`, `=` or `:`. The lookbehind says a JWT may only **start at
the first character of a run**:

| Text | Character before `eyJ` | Result |
|---|---|---|
| `Bearer eyJ…`, `"eyJ…"`, `token=eyJ…` | a space, a quote, `=` | masked |
| `jwt_eyJ…` | `_`, a token character | **not masked** |

**Why the rule is needed.** On `eyJeyJeyJ…` (60 KB), without it the regex tries a match at
every one of the 20,000 `eyJ`s, and each try scans to the end of the text looking for a dot:
about a billion steps, 2.3 s. With the rule, every `eyJ` after the first has a `J` before it and
is skipped at once, so the text is scanned once: 0.8 ms.

**Why email didn't lose anything from the same rule.** An address can start with any character
of its run, so the match starts at the run's beginning anyway. A JWT must start with exactly
`eyJ`, so in `jwt_eyJ…` there's no allowed place to start.

| Option | `jwt_eyJ…` | Problem |
|---|---|---|
| **Token start only at a run's first character** (chosen) | not masked | a glued token leaks |
| Also allow `_` and `-` before `eyJ` | masked | an attacker sends `_eyJ_eyJ…` and it's slow again (80 KB in 1.2 s) |
| Mask any run that contains `eyJ` | masked, with `jwt_` | normal words get masked: `keyJSON.a.b` contains e-y-J |

I chose the first. In real logs a JWT comes after a space, a quote, `=`, `:` or `Bearer `, never
glued to a word, while a slow pattern can be triggered on purpose and slows down everyone using
the service. The gap is documented and has a test, `test_jwt_glued_to_a_word`. If glued tokens
ever show up, the third option is the fix.

## Deployment

A `Dockerfile` and three manifests in `deploy/`, kept to what the service needs. Every choice
is also commented in the files.

```sh
docker build -t redactor:0.1.0 .
kind create cluster --name redactor              # a throwaway local cluster (needs Docker)
kind load docker-image redactor:0.1.0 --name redactor
kubectl apply -f deploy/
kubectl rollout status deployment/redactor
kubectl port-forward service/redactor 8080:80    # then curl localhost:8080 as above
```

### Dockerfile

| Choice | Why |
|---|---|
| `python:3.12.7-slim-bookworm` | Official, slim, the exact version the tests ran on. |
| Copy only `pyproject.toml` and `redactor/`, plus a `.dockerignore` | No tests, `.git` or notes in the image. |
| `USER 10001` (not root) | If the process were taken over, it has no privileges. |
| Rules **not** copied in | They come from a ConfigMap. Without them the container exits with code `2`. |
| Exec-form `ENTRYPOINT ["redactor"]` | The process is PID 1 and gets SIGTERM directly, so graceful shutdown works. |

### Kubernetes

**`configmap.yaml`: the rules.** Generated from `rules.yaml` by `kubectl create configmap ...
--dry-run` (the command is in its header), and `test_deploy.py` fails if the two differ. The
rules are read at startup, so a change needs `kubectl rollout restart deployment/redactor`.

**`deployment.yaml`: the pods.**

| Choice | Why |
|---|---|
| `replicas: 2` | One pod can crash or be replaced while the other serves. |
| Image tag `0.1.0`, never `latest` | Every pod runs the same known build. |
| Readiness and liveness probes on `/healthz` | See [Health endpoint](#health-endpoint). |
| Requests `100m` CPU / `64Mi`, limit `256Mi` memory | Idle uses 32 MiB; 8 clients with 1 MB lines peaked at 153 MiB. Over the limit the pod restarts instead of starving its node. |
| No CPU limit | Going over only slows the pod down, and one Python process uses about one core anyway. |
| `runAsNonRoot`, read-only filesystem, no privilege escalation, all capabilities dropped | It only reads its rules and talks HTTP; anything else is attack surface. |

**`service.yaml`: one stable address.** Pods come and go; the Service gives them one name,
`http://redactor` on port 80. `ClusterIP` keeps it inside the cluster: raw logs with secrets
shouldn't cross the internet.

### Health endpoint

`GET /healthz` returns `200 {"status":"ok"}`, used for both probes. **Readiness:** the port
only opens after the rules loaded, so a pod that answers can redact. **Liveness:** the event loop
answers it, and since redaction runs in threads, a busy pod still answers in milliseconds and
isn't mistaken for a stuck one.

## Known limitations

Most leaks below have a strict expected-failure test in `tests/test_known_gaps.py`.

- **A JWT glued to a letter, digit, `_` or `-`** (`jwt_eyJ…`) isn't masked (see
  [the trade-off](#the-trade-off-a-jwt-glued-to-a-word-isnt-matched)).
- **Percent-encoding and HTML entities inside a sentence** aren't decoded
  (`see email=gina%40example.com`). A whole form body or URL *is* decoded.
- **base64** isn't decoded: it can't be told apart from ordinary tokens.
- **SSNs and phone numbers in free text** aren't detected. Fields *named* `ssn` or `phone` are.
- **Cards with mixed separators** (`4111 1111-1111 1111`) aren't matched.
- **Names, addresses and dates of birth in free text** can't be found by a regex.
- **A bare value in free text ends at a space**: `password=correct horse` masks only `correct`.
  Quoted values are masked whole.
- **Over-redaction** is possible: any word after a sensitive key name in free text is masked, and
  an integer that passes Luhn is redacted like a card.

Service: there is **no limit on concurrent requests** (about 14 requests with 1 MB lines fill the
256 MiB limit, then the pod restarts, without leaking), **no TLS or authentication** (it is
only reachable inside the cluster), and **changing rules needs a pod restart** (`--watch-rules`
is CLI only). The deployment hashes with plain SHA-256: `--hmac` isn't wired up there.

## What I'd do with more time

- **The two bonuses in Kubernetes**: the HMAC key from a Secret (see
  [Hashing](#hashing-is-sha-256-safe)), and the rules watcher in the service, with failed
  reloads reported on `/healthz`.
- **SSN and phone value rules** with validators: `\b\d{3}-\d{2}-\d{4}\b` for SSNs, and only
  `+`-prefixed international numbers for phones, to keep false positives on IDs and dates low.
- **A faster `jsonio` writer**: hand the parts with nothing special to the C `json.dumps`.

## Running inline with a sub-millisecond budget

Claude measured the numbers, the results are: the redaction itself takes about 120 µs per line, but an HTTP round trip to the service costs about 0.9 ms before any work is done, so the first change is where it runs. I'd make the redactor a library where the traffic is handled and not a separate service so the setup work done once and not every request.

If a request still can't be redacted in time (for example a very big body), I wouldn't let it
through unredacted, and I wouldn't slow the system down either. What we protect is the log copy,
not the live request, so the request continues as it is, and in the log its body is replaced by a
placeholder, like the error records the tool already writes. The headers are still redacted,
because checking them is fast.

Other thing I'd do is rewrite it in Go. Go is compiled to machine code ahead of time, while
Python interprets the code as it runs, so the same work takes several times less CPU. Go's regex
engine always runs in linear time so the slowest requests stay close to the average ones, which is what a hard
budget per request needs.

## Assumptions

- Each line is one transaction object. `response`, if present, is an object with the same
  shape (`status`, `headers`, `body`).
- Query parameters (in `path`) and form fields count as **body** for key-rule scopes.
- The sample data is synthetic (as the brief says). All test data in this repo is too.
- Output order equals input order. Blank lines are not reproduced.
