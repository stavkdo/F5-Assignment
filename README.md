# API Traffic Log Redactor

A command-line tool that reads API traffic logs as NDJSON (one HTTP transaction per line),
redacts sensitive data (credentials, tokens, emails, card numbers, personal data) according to
rules in a YAML file, and writes the same NDJSON with the secrets replaced. It streams, so the
input can be far larger than memory, and it never crashes on a bad line.

## Why Python

I wrote this in Python because it's the language I know best, and so I could explain the code.
I don't know Go but I'm willing to learn.


Where Python costs me:

- **Speed.** Every line is parsed into Python objects and walked by an interpreter. The regex
  engine itself is C, but the glue around it isn't. See [Streaming](#streaming) for measured numbers.
- **Startup.** About 0.2 s of interpreter start-up per CLI run. Fine for a batch tool, and a
  service pays it only once.
- **Parallelism.** The GIL means one Python process uses one core for this CPU-bound work. A
  worker pool would need processes instead of threads.

A Go port would keep the same structure (rules → engine → stream → CLI). One thing would change:
Go's `regexp` (RE2) has no back-references, so the card pattern's "same separator throughout"
check (`\1`) would move from the regex into the validator.

Dependencies, kept to the minimum:

| Dependency | Why |
|---|---|
| PyYAML | The rules are YAML, and Python's standard library has no YAML parser. Loaded with `safe_load`, which can't build arbitrary objects. |
| pytest (dev only) | Test runner. Parametrised tests keep the edge-case tables short. |

Everything else (JSON, regex, hashing, URL decoding) is the standard library.

## Build, run and test

### Requirements

Python 3.11 or newer.

```sh
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"            # installs PyYAML, pytest and the `redactor` command
```

### CLI

```sh
redactor [--rules rules.yaml] [--max-line-bytes N] [input-file]   # reads stdin if no file is given

redactor --rules rules.yaml input.ndjson > redacted.ndjson
cat input.ndjson | redactor > redacted.ndjson
python -m redactor input.ndjson    # same thing without installing
```

- **stdout:** the redacted NDJSON, one line per input line (blank lines are skipped).
- **stderr:** one line per problem (`redactor: line 20: invalid JSON`), then a summary at the end:

```text
redactor: 50 lines read: 43 redacted, 5 replaced by an error record, 2 blank skipped
  errors: invalid JSON 3, not a JSON object 2
  redactions per rule:
    auth-headers        9
    api-key-names       7
    secret-fields       13
    ...
```

- **Exit codes:** `0` done (even if some lines were bad: they are reported, not fatal),
  `2` the rules or the input file can't be read, `1` an I/O error while streaming, `130` Ctrl-C.

On Windows PowerShell 5.1, redirecting a native program's output with `>` re-encodes it, so
use `cmd /c "python -m redactor input.ndjson > out.ndjson 2> err.txt"` to get clean UTF-8 files.

### Service mode

<!-- Phase 5: how to start it, how to call POST /redact, and what the health endpoint returns. -->

### Tests

```sh
python -m pytest            # all tests
python -m pytest -rx        # also list the known gaps (expected failures) and why
```

| File | What it covers |
|---|---|
| `test_rules.py` | Loading the YAML; every kind of invalid config is rejected at startup |
| `test_actions.py` | mask, partial, hash, remove, the Luhn check |
| `test_engine.py` | Value rules in a string, the recursive walker, key rules, whole records |
| `test_jsonio.py` | Numbers, repeated keys, NaN, unicode and lone surrogates survive a round trip |
| `test_failures.py` | Bad lines become error records; nothing from the line reaches stdout/stderr; deep nesting; invalid UTF-8 |
| `test_key_matching.py` | Case, arrays, `null`/numbers/objects under a sensitive key, near-miss names, repeated keys |
| `test_body_shapes.py` | JSON inside strings, form bodies, `key=value` in free text, URLs and the `path` query |
| `test_value_rules.py` | Card layouts, non-cards that must stay, cards stored as JSON numbers, credentials in URLs, rule order, unicode, regex speed |
| `test_idempotency.py` | `redact(redact(x)) == redact(x)` over the whole sample file and per action |
| `test_streaming.py` | Memory stays flat as the input grows; a huge line is never held in memory |
| `test_fixtures.py` | Golden files: real sample lines in, hand-checked output out |
| `test_cli.py` | The real command: files, stdin, flags, exit codes |
| `test_known_gaps.py` | Known gaps written as strict expected failures (see [Known limitations](#known-limitations)) |

## Project layout

```text
rules.yaml            the redaction rules (config, not code)
redactor/
  rules.py            YAML -> validated rule objects, regexes compiled once
  actions.py          mask / partial / hash / remove and the luhn validator: small pure functions
  jsonio.py           JSON read/write that keeps numbers, repeated keys and odd characters intact
  engine.py           Redactor: one line in, one redacted line out. Knows nothing about files
  stream.py           line-by-line driver: line size limit, error records, summary
  cli.py              argument parsing, exit codes
tests/                pytest suite and golden fixtures
```

The layers only depend downwards (cli → stream → engine → rules/actions/jsonio). The engine
works on one string at a time and the stream works on any binary file-like object, so the HTTP
service can reuse both without changes.

## Design decisions and trade-offs

### What the engine reads: "headers" and "body"

A line is a transaction object with a `response` object inside it. Both are treated the same:

- the `headers` field is walked with the **headers** scope;
- **every other field** (`body`, `path`, `ts`, `method`, `status`, and any field I don't know
  about) is walked with the **body** scope.

The second point is *default deny*: if a line arrives with an unexpected top-level field like
`"query": {"password": ...}`, it gets redacted instead of passed through because nobody listed
it. Fields like `ts` and `status` simply contain nothing that matches.

Anything decoded out of a string (JSON inside a string, a form body, a query string) is payload,
so its keys use the body scope, even when the string sat in a header.

### Rule order and overlaps

1. For each key in an object, the **first matching key rule** (in config order) wins, and its
   action is applied to the whole value. Value rules don't run on that value, so a key rule and
   a value rule never both count the same secret.
2. Otherwise the value is walked, and every string goes through **all value rules in config
   order**, each one working on the previous one's output.

Order matters where patterns overlap. `jwt` runs before `credit-card`, so digits inside a token
are masked as part of the token and never mistaken for a card. `email` runs first, and its hash
output contains no `@`, so later rules can't match inside it.

### Recursion

The walker is a recursive function over the JSON tree: objects (key rules, then recurse),
arrays (recurse), strings (decode or value rules), integers (value rules, see
[Numbers](#numbers)), and other numbers, booleans and null (kept). Recursion mirrors the data's
shape, which makes it short and easy to check.

Its weakness is the call stack. Python allows about 1000 frames, and a hostile line like
`[[[[...]]]]` 5000 levels deep used to crash the tool with `RecursionError`. Now there is an
explicit limit, `MAX_DEPTH = 100` levels (real traffic rarely passes ~20). A deeper line becomes an
error record (`nesting too deep`). `RecursionError` is also caught, both while parsing and as a
backstop, so it can never escape. An explicit stack (a loop) would remove the limit entirely,
but that would make the code harder to read, and no real log is 100 levels deep.

### Decoding nested encodings, and why it stops at 3

The brief asks for secrets inside non-JSON bodies, so a string is inspected before value rules run:

| The string is... | What happens |
|---|---|
| JSON (`{...}`, `[...]`, or a JSON string, i.e. double-encoded) | Parsed, walked like any other JSON, and written back, but **only if something was redacted**. Otherwise the original text is kept byte for byte. |
| A URL with a query (`/v1/reset?token=...`) | The query is handled as a form. |
| Form-encoded (`email=bob%40example.com&password=...`) | Each name/value is percent-decoded. Key rules match the name, value rules the decoded value. Only changed pairs are re-encoded. |
| Anything else (plain text, HTML, logs) | Free text: `key=value` / `key: value` pairs whose key is a sensitive name are redacted, then the value rules run. |

In free text a key rule applies **whatever its scope**: `Authorization: Bearer ...` pasted
into a body is still a credential, and we can't tell where the text came from.

Decoding stops after **3 levels** (`MAX_DECODES`), for example a JSON string in a form field in
a JSON string. "Decode as much as possible" sounds safer but isn't:

- each level is another full parse, and an attacker controls how many levels there are;
- each extra decoder (base64, gzip, HTML entities...) adds false positives, because almost any
  token "is" base64, and compressed data can be a decompression bomb;
- whatever is decoded must be re-encoded exactly, or idempotency breaks.

So I only decode formats that **announce themselves** and **round-trip losslessly** (JSON, form
encoding, URL queries). Past the limit the engine **fails closed**: if there is still JSON
inside, the line becomes an error record. It isn't passed through unread, because the inner
quotes are escaped and even the free-text scan couldn't see the keys.

### Streaming

Input is read as **bytes, one line at a time**, never the whole file. Each line is parsed fully,
redacted, written, and dropped before the next is read.

I parse each line fully instead of using a streaming JSON tokenizer because a line is a
self-contained unit, usually a few KB. Holding one line as a tree makes key rules, repeated keys
and rewriting embedded JSON straightforward. A tokenizer only pays off for single documents too
big for memory, and the line size limit covers that case.

**One enormous line.** Without a limit, one 10 GB line would be read into memory whole.
`--max-line-bytes` (default 1 MiB) caps it. A longer line is read in chunks and thrown away, so
it never sits in memory, and it is replaced by a `line too long` error record.

**Complexity**, for an input of *B* bytes, *V* value rules and a longest line of *L* bytes:

- **Time: O(B × V).** Each byte is parsed once, and each string is scanned once per value rule.
  Key-rule lookup is O(K) per key for *K* key rules (small and fixed). This holds only if
  **every regex runs in linear time**, which Python's `re` doesn't guarantee (see below).
- **Memory: O(L)**, independent of the input size. The parsed tree of one line is a constant
  factor larger than the line. The per-rule counters are O(number of rules).

Measured with a small local benchmark script (the sample file repeated, on my laptop, Python 3.12):

| Lines | Input | Time | Throughput | Peak Python memory (tracemalloc) |
|---|---|---|---|---|
| 10,000 | 2.2 MB | | | 16 KiB |
| 100,000 | 22 MB | | | 14 KiB |
| 1,000,000 | 221 MB | 121 s | 8,239 lines/s, 1.8 MB/s, ~121 µs per line | |

Ten times more input, the same memory: it's flat. The memory test in `test_streaming.py`
checks the same thing on every test run. Throughput is where Python costs me. I haven't
measured a Go version. A compiled one should be several times faster, and a worker pool would
scale either one with cores.

#### Regexes are part of the time complexity

Python's `re` is a *backtracking* engine. How long a pattern takes depends on what the input
looks like, not just on its length. Since the input is traffic someone else controls, a pattern
that becomes slow on some input is a denial-of-service hole (often called ReDoS). I measured
every rule on 14 kinds of hostile 1 MB bodies (long letter runs, base64, digits, `a:a:a:…`,
`password=password=…`, …). Two of the provided patterns were quadratic.

**Why the provided email pattern was O(n²).** The pattern starts with
`[A-Za-z0-9._%+-]+@`. To find the leftmost match, `re` tries start position 0, then 1, then 2, and
so on. Take a run of *n* letters with no `@`, for example a base64-encoded upload:

- starting at position *i*, `[…]+` greedily takes the remaining *n − i* letters, finds no `@`,
  and gives them back one by one, checking for an `@` each time: about *n − i* steps before it fails;
- over all start positions that is *n + (n − 1) + … + 1 = n(n + 1)/2* steps, which is **O(n²)**.

Measured: 5 KB took 44 ms, 10 KB 183 ms, 20 KB 715 ms. Each doubling of the input quadruples
the time, the signature of O(n²). A single 1 MB line would take about half an hour.

**The fix** is a lookbehind in front: `(?<![A-Za-z0-9._%+-])`, meaning "the character before
this one can't be part of an address". It is checked in O(1) at each position and fails at
every position *inside* a run, so only the first character of each run does the scan. Runs don't
overlap, so the total is **O(n)**: 1 MB now takes 16 ms.

**It finds exactly the same matches.** If an address ends at some `@`, the scan that starts at
the first character of that run reaches the same `@`, and it is tried first, so the leftmost
match always starts at a run's beginning. The positions the lookbehind skips could never have
produced a match.

**Can it be faster than O(n)?** Not asymptotically. A correct detector has to look at every
character at least once, because any unread character could be the `@`. So Ω(n) is a lower
bound, and the fixed pattern meets it. Only the constant factor could shrink. For example, a
possessive quantifier (`[…]++`, Python 3.11+) skips the give-back walk and roughly halves the
work per run. Without the lookbehind, though, that would still be O(n²), because every start
position would still scan to the end of the run.

| Rule | Hostile input | Before | Now |
|---|---|---|---|
| `email` | 20 KB of letters or base64, no `@` | 0.7 s (1 MB ≈ 30 min) | 1 MB in 16 ms (lookbehind) |
| `jwt` | `eyJeyJeyJ…` | 50 KB in 1.75 s | same shape of problem, fixed together with the JWT report (3f); strict xfail test until then |

Every other rule grows linearly (1 MB of the worst shape takes under a second), and the tests
time the worst cases so a regression shows up. Go's RE2 engine guarantees linear time by
design, which is one real argument for Go here.

### Rule matching

- Every regex is **compiled once** when the rules load, never per line.
- `exact` key names are compared **case-insensitively** (HTTP header names are case-insensitive).
  `regex` key rules use `(?i)` and are **anchored** (`^...$`), so `password_hint`,
  `passwordless`, `tokenizer` and `secret_santa` don't match.
- A value rule can name a **validator**: a pure function that gets the matched text and
  returns true/false. `luhn` rejects about 90% of random 16-digit numbers, which is why the order
  reference `4111111111111112` and the timestamp `1705312800123456` survive. `luhn` counts
  every Unicode digit, the same set the regex `\d` matches, so a card written in full-width
  (`４１１１…`) or Arabic-Indic digits is checked and masked like any other. It used to read only
  `0-9`, so such cards matched the regex, failed the check, and leaked. Adding a validator is
  one function in `actions.py` plus one entry in `VALIDATORS`.
- **Config errors fail at startup** (unknown action, scope or validator, bad regex, both or
  neither of `exact`/`regex`, duplicate names): the tool exits with code 2 before reading a
  line, so it can never run with rules it half understands.

### Changes to rules.yaml

The brief allows changing the config with a reason. All changes are in `rules.yaml` itself,
none in code:

| Change | Why |
|---|---|
| `credit-card` pattern now also matches cards printed in groups: 4-4-4-4, 4-6-5 (Amex), 4-6-4 (Diners), with spaces or dashes | `\b\d{13,19}\b` missed `4111 1111 1111 1111` and `5555-5555-5555-4444` (sample lines 1, 6, 36, 44). |
| `pii-fields` key rule: `ssn`, `phone`, `dob` and similar names, mask | Sample line 37. A field *named* `phone` is a phone number, so matching on the name has almost no false positives. |
| `url-credentials` value rule, `(?<=://)[^/\s:@]+:[^/\s@]+(?=@)`, mask, placed **before** `email` | `postgres://admin:hunter2@db:5432/app` leaked: no rule covered it. With a host like `db.internal` the email rule hashed `hunter2@db.internal` by accident, leaving the user name readable and the password open to guessing. Now the result is `postgres://****@db:5432/app`. The `://` lookbehind pins each match to the start of a URL, which also keeps it linear. A URL with only a user name (`https://user@host`) is left alone. |
| `email` pattern gets the lookbehind `(?<![A-Za-z0-9._%+-])` | Same matches, but linear instead of quadratic time (see [Regexes are part of the time complexity](#regexes-are-part-of-the-time-complexity)). |

Why the card pattern lists layouts instead of "digits with optional separators": a loose
`(\d[ -]?){12,18}\d` on `"id 1 4111 1111 1111 1111"` starts matching at the `1`, takes 17
digits, fails Luhn, and the real card leaks, because `re.sub` never retries a shorter match
after the validator says no. Listing real layouts, plus the back-reference `\1` that requires
the same separator throughout, avoids that.

**Not added: SSN and phone value rules.** The brief asks to detect "at minimum: emails, JWTs,
credit card numbers, and credentials in headers". SSNs and phones aren't on that list, so in
free text they are a documented gap. Fields *named* `ssn` or `phone` are still masked by
`pii-fields`. Both rules are in [What I'd do with more time](#what-id-do-with-more-time), with
their trade-offs.

### Numbers

Value rules also read **integer** literals, as their digits. A card stored as a JSON number
under a harmless key (`"amount": 4111111111111111`) is still a card, so it is redacted, and
because `partial` produces text it becomes a string: `"************1111"`. Every number that
isn't redacted keeps its type and exact text. Numbers with a sign, fraction or exponent
(`-4111…`, `4111….0`, `1e3`) are left alone: a card is never written that way.

The cost is false positives with a type change. Luhn accepts about 1 in 10 random numbers
(measured: 10.1% of random 16-digit numbers), so an integer ID or timestamp of 13–19 digits
has a 10% chance of being redacted like a card. Line 35's timestamp `1705312800123456` fails
Luhn and stays a number; `1705312800123452` would become `"************3452"`. I chose leak
safety over type stability here. A team that prefers the opposite could make this a config option.

### Sensitive keys with non-string values

| Value under a sensitive key | Result | Why |
|---|---|---|
| string | the action | |
| number (`"card_number": 4111111111111111`) | the action on its text, so it becomes a string | `partial`/`hash` need text, and the digits must not survive |
| `null`, `true`, `false` | kept | they contain no secret, and keeping them keeps the type |
| array / object (`"Set-Cookie": ["a", "b"]`) | the action on every scalar inside, shape kept → `["****", "****"]` | downstream tools still see a list |
| anything, with `remove` | the key is dropped | |

### Failure handling

A line that can't be processed (invalid JSON, valid JSON that isn't an object, too deep, too
long) is replaced on stdout by an **error record**, and reported on stderr:

```text
stdout:  {"redactor_error":{"line":20,"reason":"invalid JSON"}}
stderr:  redactor: line 20: invalid JSON
```

| Option | Safety | Data loss | Downstream parsers |
|---|---|---|---|
| Pass the line through | ❌ leaks | none | may break |
| Redact it as plain text | ⚠️ leaks what the rules can't see: line 20's half JWT, line 21's `user=` | low | may break |
| Drop it silently | ✅ | **silent**: nobody downstream knows a line is missing | ✅ |
| **Error record** (chosen) | ✅ contains no input | visible: says which line and why | ✅ still valid NDJSON |

**No leaks in errors.** The reason is always one of a **fixed set of strings**: `invalid JSON`,
`not a JSON object`, `nesting too deep`, `line too long`, `internal error`. It is never
`str(exception)`, because Python's error messages can quote the input (`UnicodeDecodeError`
includes the offending bytes). There's no traceback either: an unexpected exception in one line
becomes an `internal error` record and the stream goes on.

Other choices:

- A failed line's rule counts are **discarded**, so the summary only counts what was written.
- **Blank lines** are skipped and counted, not reported as errors. NDJSON readers may skip them.
- **Invalid UTF-8** bytes are replaced with U+FFFD and the line is still redacted. Replacing
  only removes information, and stderr says which line.
- `NaN`/`Infinity` are rejected as invalid JSON. Python accepts them, but other parsers don't.

### Idempotency

`redact(redact(x)) == redact(x)`, tested over the whole sample file. `mask`, `partial` and
`remove` already have this property (masking `****` gives `****`). `hash` doesn't:
`sha256(sha256(x)) ≠ sha256(x)`. Before this was fixed, five sample lines changed on a second run.

The fix makes hash output **recognisable**: it is written as `sha256:<64 hex>`. A hash rule
leaves a value alone if it is already a hash, or is the mask string left by an earlier
redaction (sample line 12 has `"X-Api-Key":"****"`, and hashing `****` would pretend there was
a real key). I didn't use "any 64-hex string" as the test, because a real secret can be 64 hex
characters, and skipping it would leak it.

The decoders are stable too: embedded JSON is only rewritten if something changed, and our
compact output reads back to the same text. Form pairs are only re-encoded if they changed.

### Hashing: is SHA-256 safe?

The brief defines `hash` as "the SHA-256 of the value", and `rules.yaml` says
`algorithm: sha256`, so that's what the tool does. But plain SHA-256 is **not** safe for
cards or emails. SHA-256 can't be reversed, but it can be *guessed forwards*, and these inputs
come from small spaces:

- a 16-digit card has 6 known bank-prefix digits, 4 digits often shown elsewhere (`partial`
  shows them!) and 1 Luhn check digit, leaving about 10⁵ candidates, a fraction of a second on a laptop;
- emails can be tried from leaked email lists or guessed for a specific target.

The fix I'd make with more time is **HMAC-SHA256 with a secret key** (from a Kubernetes Secret).
Equal inputs still give equal outputs, so analysts can still correlate "same user", but without
the key nobody can test guesses. The costs are key management, and rotating the key breaks
correlation with older logs.

### Output format

The output is the same JSON, written compactly on one line. Compared to the input:

- **kept:** key order, every number literal exactly as written (`10.50`, `1e3`,
  `12345678901234567890`), repeated keys (`json.loads` would silently keep only the last one,
  sample line 25), non-ASCII text as readable UTF-8;
- **changed:** whitespace between tokens (removed), and escapes may be written differently
  (a non-ASCII character escaped in the input as backslash-u plus four hex digits is written as
  the character itself, e.g. `ÿ`; same string);
- **lone surrogates** (`"\ud800"`, valid JSON text but not valid UTF-8) are kept as `\u`
  escapes. Writing them raw used to crash the output stream.

#### Why `jsonio.py` exists

A redactor should change the secrets and nothing else: the rest of the log should look exactly
as the redactor received it. Python's `json` doesn't do that. A plain `json.loads` then
`json.dumps` rewrites `10.50` as `10.5` and `1e3` as `1000.0`, keeps only the last value of a
repeated key (`{"a":1,"a":2}` becomes `{"a":2}`), and accepts `NaN`, which isn't JSON.

`jsonio.py` is not a parser of its own. The parsing is still done by the standard library's
`json.JSONDecoder` (its C scanner), with four hooks: numbers are kept as their original text,
an object with a repeated key is kept as a list of pairs (objects without one stay plain
dicts), and `NaN`/`Infinity` are rejected. A matching writer (about 30 lines) writes numbers
back as that text and writes repeated keys back in order.

I checked the libraries first. `orjson`, `ujson` and `rapidjson` parse into floats and dicts,
so they lose the same things. `simplejson` with `use_decimal` keeps `10.50` but rewrites `1e3`
as `1E+3`, and repeated keys would still need a custom writer. None of them gives "change some
strings, write the rest back as it was", and each would be an extra dependency.

The brief doesn't require this (plain `json` would also be idempotent), so it's a choice, and
it has a cost. Measured on the sample lines: reading takes 4.7 µs per line instead of 3.0, since
the parser is still C, but the writer is pure Python, 20.9 µs instead of 4.6. That's about 18 of
the ~105 µs per line, roughly 17%. The complexity is the same, O(L) per line; only the
constant changes. I kept it, because a log that's changed in places that weren't secrets is
harder to trust. The cost can be cut without giving up the fidelity (see
[What I'd do with more time](#what-id-do-with-more-time)).

## The JWT report

<!--
Phase 3f, not done yet. Tell it as a short debugging story:
- Symptom: what users reported
- Reproduction: which sample lines show it (11, 15, 16), and the failing test (tests/test_known_gaps.py)
- Root cause
- Fix: what changed in rules.yaml (link the commit)
-->

## Deployment

### Dockerfile

<!-- Phase 6: base image, non-root user, pinned versions, where the rules file comes from. Why each choice. -->

### Kubernetes

<!-- Phase 6: Deployment, Service, ConfigMap, probes, resource requests/limits. Why each one. -->

### Health endpoint

<!-- Phase 5: path and meaning (liveness vs readiness). What "healthy" means for this service. -->

## Known limitations

Each leak below has a strict expected-failure test in `tests/test_known_gaps.py`. If one gets
fixed, its test fails until the marker is removed, so this list can't silently go stale.

- **JWTs in base64url are only partly masked** (sample lines 11, 15, 16), and the `jwt`
  pattern is **quadratic** on input like `eyJeyJeyJ…`. This is the user report, to be fixed in
  its own commit (Phase 3f).
- **Percent-encoding and HTML entities inside a sentence** aren't decoded:
  `see email=gina%40example.com for details` and `<p>alice&#64;example.com</p>` keep the email.
  Percent-encoding *is* decoded when the whole string is a form body or a URL. Decoding single
  words inside prose would work, but it costs: a rewritten word can't keep its exact original
  encoding, you can never cover every encoding (double encoding, mixes), and it's more code. The
  brief asks for form and plain-text bodies, which are covered, so this is planned only after
  everything else (see [What I'd do with more time](#what-id-do-with-more-time)).
- **base64** isn't decoded (see [decoding](#decoding-nested-encodings-and-why-it-stops-at-3)).
- **SSNs and phone numbers in free text** aren't detected (no value rules, see
  [Changes to rules.yaml](#changes-to-rulesyaml)). Fields named `ssn` / `phone` are masked.
- **Cards with mixed separators** (`4111 1111-1111 1111`) and **19-digit cards printed in
  groups** aren't matched.
- **Names, addresses and dates of birth in free text** can't be found by a regex.
- **Free-text `key=value` detection** stops a bare value at whitespace, so
  `password=correct horse` only masks `correct`, and `phone: +1 (415) 555-0132` only masks
  `+1`. Quoted values are masked whole.
- **Over-redaction** is possible: any word after a sensitive key name followed by `:` or `=` in
  free text is masked, and an integer of 13–19 digits that happens to pass Luhn is redacted like
  a card (see [Numbers](#numbers)).
- **Embedded JSON that gets rewritten** loses its original spacing (only when something in it was redacted).

## What I'd do with more time

- HMAC-SHA256 instead of plain SHA-256 (see [Hashing](#hashing-is-sha-256-safe)).
- **An SSN value rule**, `\b\d{3}-\d{2}-\d{4}\b`. The 3-2-4 dash shape is rare elsewhere (dates
  are 4-2-2, US phones 3-3-4), so false positives are few: an order or part number written
  `555-12-3456` would be masked. It misses SSNs written with spaces or none, because allowing
  those would hit every 9-digit ID. A small validator could reject impossible SSNs (area 000,
  666 or 9xx, group 00, serial 0000), like Luhn does for cards.
- **A phone value rule** limited to numbers that start with `+` and a country code (IDs rarely
  do), with a validator for 8–15 digits (the international E.164 maximum). That would also
  catch the rest of `phone: +1 (415) 555-0132`. Local formats like `0541234567` would still be
  missed. Matching every phone shape would also match timestamps, dates and order numbers.
- **Decoding single words in free text**: percent-encoding and HTML entities (see
  [Known limitations](#known-limitations)).
- **A faster writer in `jsonio.py`**: parts of a line with no numbers and no repeated keys
  could be handed to the C `json.dumps`, and only the parts that have them would go through the
  Python writer. That keeps the output identical and wins back most of the ~17% (see
  [Why `jsonio.py` exists](#why-jsoniopy-exists)).

## Running inline with a sub-millisecond budget

<!-- One paragraph: "If this had to run inline on live production traffic with a sub-millisecond budget per request, what would you change?" -->

## Assumptions

- Each line is one transaction object. `response`, if present, is an object with the same
  shape (`status`, `headers`, `body`).
- Query parameters (in `path`) and form fields count as **body** for key-rule scopes.
- The sample data is synthetic (as the brief says). All test data in this repo is too.
- Output order equals input order. Blank lines are not reproduced.
