"""Service mode: POST /redact streams NDJSON both ways, /healthz, and failing closed on bad rules."""

import asyncio
import io
import random
import socket
import threading
import time

import pytest
import uvicorn
from fastapi.testclient import TestClient

from conftest import ROOT, run_stream
from redactor.cli import main
from redactor.engine import Redactor
from redactor.service import create_app, parse_addr, split_lines
from redactor.stream import read_lines

SAMPLE = (ROOT / "input.ndjson").read_bytes()


async def _chunks(pieces):
    for piece in pieces:
        yield piece


def split(pieces, max_bytes=1024):
    """All lines split_lines finds in the given chunks, in order."""

    async def collect():
        return [line async for batch in split_lines(_chunks(pieces), max_bytes) for line in batch]

    return asyncio.run(collect())


# --- cutting the body into lines -------------------------------------------------------------


def test_a_line_split_across_chunks_is_joined():
    assert split([b'{"a":', b"1}\n{", b'"b":2}\n']) == [b'{"a":1}\n', b'{"b":2}\n']


def test_last_line_without_newline_is_kept():
    assert split([b"one\ntwo"]) == [b"one\n", b"two"]


def test_too_long_line_is_reported_once_and_dropped_as_it_arrives():
    pieces = [b"ok\n", b"x" * 6, b"x" * 6, b"x" * 6 + b"\nafter\n"]
    assert split(pieces, max_bytes=10) == [b"ok\n", None, b"after\n"]


def test_too_long_line_inside_one_chunk():
    assert split([b"short\n" + b"y" * 11 + b"\nend\n"], max_bytes=10) == [b"short\n", None, b"end\n"]


def test_line_of_exactly_the_limit_is_allowed():
    # The same boundary as the CLI: the limit counts the line without its newline.
    assert split([b"x" * 10 + b"\n"], max_bytes=10) == [b"x" * 10 + b"\n"]
    assert split([b"x" * 11 + b"\n"], max_bytes=10) == [None]


@pytest.mark.parametrize("seed", range(20))
def test_any_chunking_gives_the_same_lines_as_the_cli_reader(seed):
    rng = random.Random(seed)
    data = SAMPLE + b"z" * 300 + b"\n" + SAMPLE  # includes a too-long line for max_bytes=200
    cuts = sorted(rng.sample(range(1, len(data)), 40))
    pieces = [data[a:b] for a, b in zip([0] + cuts, cuts + [len(data)])]
    assert split(pieces, max_bytes=200) == list(read_lines(io.BytesIO(data), 200))


# --- the HTTP endpoints --------------------------------------------------------------------


@pytest.fixture
def client(rules):
    return TestClient(create_app(rules))


def test_redact_endpoint_matches_the_cli(client, rules):
    response = client.post("/redact", content=SAMPLE)
    expected, _, _ = run_stream(Redactor(rules), SAMPLE)
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/x-ndjson"
    assert response.text.splitlines() == expected


def test_bad_lines_become_error_records_over_http(client):
    response = client.post("/redact", content=b'{"body":{"password":"x"}}\nnot json\n')
    assert response.text == '{"body":{"password":"****"}}\n{"redactor_error":{"line":2,"reason":"invalid JSON"}}\n'


def test_empty_body_gives_empty_response(client):
    response = client.post("/redact", content=b"")
    assert (response.status_code, response.text) == (200, "")


def test_healthz(client):
    response = client.get("/healthz")
    assert (response.status_code, response.json()) == (200, {"status": "ok"})


def test_wrong_method_and_no_docs(client):
    assert client.get("/redact").status_code == 405
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_requests_dont_share_counts(rules):
    # Each request gets its own Redactor, so concurrent requests can't mix their per-line counts.
    app = create_app(rules)
    with TestClient(app) as c:
        a = c.post("/redact", content=b'{"body":{"password":"x"}}\n')
        b = c.post("/redact", content=b'{"body":{"password":"y"}}\n')
    assert a.text == b.text == '{"body":{"password":"****"}}\n'


# --- a real server: streaming both ways --------------------------------------------------


@pytest.fixture
def server(rules):
    """The app on a real uvicorn server on a free port, in a background thread."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    # The shutdown deadline makes a stuck request fail the test instead of hanging the run.
    config = uvicorn.Config(create_app(rules), log_level="warning", ws="none", timeout_graceful_shutdown=1)
    srv = uvicorn.Server(config)
    thread = threading.Thread(target=srv.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not srv.started:
        assert time.monotonic() < deadline, "server didn't start"
        time.sleep(0.02)
    yield port
    srv.should_exit = True
    thread.join(10)
    sock.close()


def test_output_streams_before_the_body_ends(server):
    """Each line's redaction comes back before the next line is even sent.

    This is "don't buffer the whole body" in both directions. It also guards against the bug
    Starlette's own StreamingResponse has here: its disconnect listener swallowed body chunks
    that arrived after the response started, and this exchange got an empty response.
    """
    s = socket.create_connection(("127.0.0.1", server), timeout=5)
    try:
        s.sendall(b"POST /redact HTTP/1.1\r\nHost: test\r\nTransfer-Encoding: chunked\r\n\r\n")
        received = b""
        for i in range(3):
            line = b'{"body":{"password":"secret%d"}}\n' % i
            s.sendall(b"%x\r\n%s\r\n" % (len(line), line))
            while received.count(b'"password":"****"') < i + 1:
                data = s.recv(4096)
                assert data, "connection closed early"
                received += data
            assert b"secret" not in received
        s.sendall(b"0\r\n\r\n")
        while not received.endswith(b"0\r\n\r\n"):
            received += s.recv(4096)
        assert received.startswith(b"HTTP/1.1 200")
    finally:
        s.close()


# --- starting up: fail closed ----------------------------------------------------------------


@pytest.mark.parametrize("content", [
    "key_rules: [",  # invalid YAML
    "",  # empty file
    "version: 1\n",  # valid, but no rules: would redact nothing
    "version: 1\nkey_rule:\n  - {name: s, match: {exact: [password]}, action: mask}\n",  # misspelled section
])
def test_serve_refuses_to_start_without_usable_rules(tmp_path, capsys, content):
    # main() returns before serve() is called, so no port is ever opened: there is no moment
    # when the service accepts traffic it can't redact.
    bad = tmp_path / "rules.yaml"
    bad.write_text(content, encoding="utf-8")
    assert main(["--serve", "--rules", str(bad)]) == 2
    assert capsys.readouterr().err.startswith("redactor: ")


def test_serve_refuses_to_start_when_the_rules_file_is_missing(tmp_path):
    assert main(["--serve", "--rules", str(tmp_path / "missing.yaml")]) == 2


def test_serve_rejects_a_bad_address(capsys):
    assert main(["--serve", "--rules", str(ROOT / "rules.yaml"), "--addr", "8080"]) == 2
    assert "invalid address" in capsys.readouterr().err


def test_serve_and_an_input_file_dont_mix(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--serve", "input.ndjson"])
    assert e.value.code == 2


@pytest.mark.parametrize("addr, expected", [
    (":8080", ("0.0.0.0", 8080)),
    ("127.0.0.1:9000", ("127.0.0.1", 9000)),
    ("localhost:1", ("localhost", 1)),
])
def test_parse_addr(addr, expected):
    assert parse_addr(addr) == expected


@pytest.mark.parametrize("addr", ["8080", ":", ":abc", ":0", ":70000", "host:"])
def test_parse_addr_rejects(addr):
    with pytest.raises(ValueError):
        parse_addr(addr)
