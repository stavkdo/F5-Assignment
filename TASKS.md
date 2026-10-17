# Task List: API Traffic Log Redactor (Python)

Plan: get a **basic filter** working on ordinary data first, then work through the edge cases.
Commit after every checkbox group. The commit history is part of the grade.

Each phase ends with **Decisions to defend**. Write your answer in one sentence
before you write the code. If you can't, the design isn't settled yet.

Rough time budget: ~6h in total. The phases are in brief-priority order.

---

## Phase 0: Setup (~20 min)

- [x] `git init` (done)
- [ ] Add `.gitignore` (Python stuff, `.venv/`, `__pycache__/`, `download`/`.DS_Store`)
- [ ] First commit: the provided files exactly as received (`BRIEF.md`, `rules.yaml`, `input.ndjson`)
      so later diffs to `rules.yaml` (JWT fix) are visible
- [ ] Pick the Python version and create a virtualenv
- [ ] Pick dependencies: a YAML parser (stdlib has none) and a test runner
- [ ] Create the project layout (package dir, tests dir, entry point)
- [ ] Add a stub `README.md` with the "why Python" note

**Decisions to defend**
- Why Python and not Go? Where will Python cost you (speed, startup, GIL)?
- Why each dependency? (Fewer is easier to defend.)

---

## Phase 1: Understand before coding (~30 min, no code)

- [ ] Pick 5 "normal" lines from `input.ndjson` (e.g. lines 1, 2, 3, 5, 12) and write
      the **expected redacted output by hand**. These become your first test fixtures.
- [ ] For each rule in `rules.yaml`, write one line on what it should do
- [ ] Settle what `scope: headers` and `scope: body` mean. Request only, or response too?
      What about `path`, `ts` and `method`?

**Decisions to defend**
- What exactly is a "header" and what is "body" in your engine?
- In what order do key rules and value rules run, and why?

---

## Phase 2: Basic filter, happy path (~1.5h)

Goal: the CLI correctly redacts well-formed lines with ordinary data.

### 2a. Rules config
- [ ] Load the YAML into rule objects
- [ ] Compile regexes **once** at load time
- [ ] Validate: unknown action, bad regex, or unknown validator means **fail loudly** at startup
- [ ] Tests: valid config loads; each kind of invalid config is rejected

### 2b. Actions and validator
- [ ] `mask`, `partial`, `hash`, `remove` as small pure functions
- [ ] `luhn` validator
- [ ] Tests: each action, Luhn with known-valid and known-invalid numbers

### 2c. Value rules on one string
- [ ] Apply every value rule to a single string, replacing matches **inside** the text
- [ ] Count each match per rule
- [ ] Tests: email in a sentence, card in a sentence, two matches in one string

### 2d. Recursive walker
- [ ] Walk any JSON value: dict, list, string, or other
- [ ] Dict keys go through key rules; strings go through value rules
- [ ] Tests: nested dicts, lists of dicts, deep nesting

### 2e. Line processing + CLI
- [ ] Parse line, redact `headers`/`body`/`response`, serialize back to one line
- [ ] CLI: `--rules`, optional input file, stdin fallback, stdout output
- [ ] Per-rule summary on **stderr** at the end
- [ ] Process input **line by line**. Never read the whole file.
- [ ] Test: end-to-end on your Phase 1 fixture lines

**Decisions to defend**
- Why parse each line fully into objects instead of using a streaming JSON tokenizer?
- How did you structure the code so the same engine serves both CLI and HTTP?
- Recursion: what is the depth limit? What happens on a deeply nested line?
- What does the JSON serializer change compared to the input (key order, spacing, unicode escapes)?

---

## Phase 3: Edge cases (~2h, one commit per group)

Write a **failing test first** for each group, then fix it.

### 3a. Failure handling *(highest priority, since "never crash" is a hard requirement)*
- [ ] Malformed lines: truncated JSON, plain log text, an empty/whitespace line
- [ ] Valid JSON that isn't an object: `42`, `["a@b.com", ...]`
- [ ] Decide **what to emit** for a line you can't safely process (drop it? emit a placeholder? redact it as plain text?)
- [ ] Error reporting on stderr that **never includes line content** (line number + reason only)
- [ ] Count errors in the summary

### 3b. Key-matching details
- [ ] Case-insensitive header names (`authorization`, `AUTHORIZATION`)
- [ ] Header values that are **arrays** (`Set-Cookie`, `Authorization` lists)
- [ ] Sensitive key with a non-string value (`null`, `0`, `false`, `[]`, a number like `card_number: 4111...`)
- [ ] Near-miss names must NOT match (`password_hint`, `tokenizer`, `secret_santa`)
- [ ] Duplicate keys in one object

### 3c. Body shapes
- [ ] String body that **contains JSON** (`/v1/legacy`, the response `body` on line 1)
- [ ] Form-encoded body (`email=bob%40example.com&password=...`)
- [ ] Plain text and HTML bodies
- [ ] Binary-looking body
- [ ] Sensitive data in `path` query string (`/v1/reset?token=...&email=...`)

### 3d. Value-rule details
- [ ] Cards with spaces/dashes (`4111 1111 1111 1111`, `5555-5555-5555-4444`, amex `3782 822463 10005`)
- [ ] Non-Luhn 16-digit numbers and long IDs/timestamps stay untouched
- [ ] Overlapping matches between rules (e.g. digits inside a JWT): order matters
- [ ] Unicode / emoji / RTL text around matches
- [ ] Big integers and floats survive unchanged (`12345678901234567890`, `1.0`, `1e3`)
- [ ] Decide on (and document) PII not covered by the rules (SSN, phone)

### 3e. Idempotency
- [ ] Test: `redact(redact(sample)) == redact(sample)` over the whole input file
- [ ] Fix the `hash`-twice problem (decide how to recognize already-redacted values)
- [ ] Check partial/mask/remove and embedded JSON also stay stable

### 3f. JWT investigation (keep this as its own commit; it's a story for the interview)
- [ ] Find the JWTs in the sample that the current pattern misses
- [ ] Write a failing test that reproduces the user report
- [ ] Find the root cause, fix `rules.yaml`, and see the test pass
- [ ] Write down the finding for the README

### 3g. Streaming guarantees
- [ ] Confirm memory stays flat on a large generated file (e.g. 1M lines)
- [ ] Decide what happens with a **single** enormous line (max line size?)
- [ ] Write down time and memory complexity

**Decisions to defend**
- Why that output for a bad line? (Think about safety vs data loss vs downstream parsers.)
- How do you avoid leaking data in error messages?
- How deep do you decode nested encodings, and why stop there?
- Plain SHA-256 of a card number or email: is it really safe? (Hint: how big is the input space?)
- Memory: O(?) Time: O(?)

---

## Phase 4: README, first full draft (~30 min)

Required sections (from the brief):
- [ ] 1. Build, run, test (CLI + service)
- [ ] 2. Design decisions & trade-offs (recursion, streaming, rule matching, failure handling)
- [ ] 3. JWT finding and fix
- [ ] 4. Deployment file notes
- [ ] 5. Known limitations / what you'd do with more time
- [ ] 6. The "sub-millisecond inline on production traffic" paragraph
- [ ] "Used Python because..." note

---

## Phase 5: Service mode (~1h)

- [ ] Choose the HTTP stack (stdlib vs a framework) based on **streaming** support
- [ ] `POST /redact`: stream the request body line by line and stream the response. No buffering.
- [ ] Health endpoint: choose the path and meaning (liveness vs readiness)
- [ ] **Fail closed**: rules fail to load means the service refuses to start, or reports not-ready and never redacts
- [ ] `--serve --addr --rules` flags on the same entry point
- [ ] Tests: happy path, malformed line in the request, rules-missing behavior

**Decisions to defend**
- How do you prove the request isn't fully buffered?
- What does "healthy" mean for this service?
- What happens to an in-flight request if a line is malformed?

---

## Phase 6: Deployment files (~45 min)

- [ ] `Dockerfile`: small base image, non-root user, pinned versions, the rules file not baked in (or baked in plus overridable)
- [ ] k8s: `Deployment` + `Service` + `ConfigMap` (rules mounted at `/etc/redactor/rules.yaml`)
- [ ] Liveness/readiness probes wired to your health endpoint
- [ ] Resource requests/limits
- [ ] Optional: try it on `kind`
- [ ] README section: what each piece is and why

**Decisions to defend**
- Every line in the Dockerfile and the manifest. If you can't explain a line, delete it.

---

## Phase 7: Bonuses (only if time is left)

- [ ] Worker pool with preserved output order
- [ ] Prometheus metrics
- [ ] Hot-reload of rules
- [ ] Anything else, with a reason

---

## Phase 8: Submission checklist

- [ ] README complete and accurate (nothing claimed that doesn't work)
- [ ] All tests pass from a clean clone
- [ ] Commit history readable, not squashed
- [ ] No real secrets or personal data in the repo
- [ ] Email reply: assumptions + anything they should know
- [ ] Rehearse: pick a random function and explain it out loud; try one small live change
