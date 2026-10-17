# API Traffic Log Redactor

<!-- One or two sentences: what this tool does and who it is for. -->

## Why Python

<!--
The brief strongly prefers Go. Explain honestly why you chose Python.
- Where does Python cost you? (raw speed, startup time, the GIL for a worker pool)
- What would change if you ported it to Go?
- Why each dependency? (PyYAML: stdlib has no YAML parser. pytest: test runner.)
-->

## Build, run and test

### Requirements

<!-- Python version, how to create the virtualenv, how to install. -->

### CLI

<!--
Show the command and one example. Hint:
    python -m redactor --rules rules.yaml input.ndjson > out.ndjson
    cat input.ndjson | python -m redactor
Mention: output goes to stdout, the per-rule summary and errors go to stderr.
-->

### Service mode

<!-- How to start it, how to call POST /redact, and what the health endpoint returns. -->

### Tests

<!-- How to run the tests, and what they cover. -->

## Project layout

<!-- One line per file/module: what lives where and why it is split that way. -->

## Design decisions and trade-offs

### What "headers" and "body" mean

<!--
Which fields of a line does the engine look at? Request only, or response too?
What about ts, method, path?
-->

### Rule order

<!-- In what order do key rules and value rules run, and why? What happens when two rules overlap? -->

### Recursion

<!-- How the walker works over dicts, lists and strings. What is the depth limit, and what happens on a very deeply nested line? -->

### Streaming

<!--
How input is read (line by line) and why you parse each line fully instead of using a streaming JSON tokenizer.
Memory complexity: O(?)    Time complexity: O(?)
What happens with a single enormous line?
-->

### Rule matching

<!-- Regexes compiled once at load time; case-insensitive header names; how validators (luhn) plug in; why config errors fail at startup. -->

### Failure handling

<!--
What do you emit for a line you can't process, and why? (safety vs data loss vs downstream parsers)
How do you guarantee error messages never contain the sensitive data?
-->

### Idempotency

<!-- How redact(redact(x)) == redact(x) is guaranteed, especially for `hash`. -->

### Hashing

<!-- Is plain SHA-256 of an email or card number really safe? (Think about the size of the input space.) What would you use instead? -->

### Output format

<!-- What the JSON serializer changes compared to the input: key order, spacing, unicode escapes, numbers like 10.50. -->

## The JWT report

<!--
Tell it as a short debugging story:
- Symptom: what users reported
- Reproduction: which sample lines show it, and the failing test you wrote
- Root cause
- Fix: what changed in rules.yaml (link the commit)
-->

## Deployment

### Dockerfile

<!-- Base image, non-root user, pinned versions, where the rules file comes from. Why each choice. -->

### Kubernetes

<!-- Deployment, Service, ConfigMap, probes, resource requests/limits. Why each one. -->

### Health endpoint

<!-- Path and meaning (liveness vs readiness). What "healthy" means for this service. -->

## Known limitations

<!-- What doesn't work or isn't covered (e.g. PII without rules: SSN, phone). Be honest: "not done" beats "claimed but broken". -->

## What I'd do with more time

<!-- -->

## Running inline with a sub-millisecond budget

<!-- One paragraph: "If this had to run inline on live production traffic with a sub-millisecond budget per request, what would you change?" -->

## Assumptions

<!-- Anything you assumed where the brief was ambiguous. -->
