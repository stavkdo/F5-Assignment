"""HTTP service mode: redactor --serve --addr :8080 --rules /etc/redactor/rules.yaml

    POST /redact   NDJSON in, redacted NDJSON out, streamed both ways (never the whole body)
    GET  /healthz  200 while the service can redact (see the README for why one endpoint)

The rules are loaded before the port is opened (see cli.py), so a service that answers at all
has valid rules: there is no state in which traffic could pass through unredacted.
"""

import asyncio
import sys
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse

from redactor.engine import Redactor
from redactor.rules import Rules
from redactor.stream import DEFAULT_MAX_LINE_BYTES, LineProcessor, format_summary

NDJSON = "application/x-ndjson"


async def split_lines(chunks: AsyncIterator[bytes], max_bytes: int) -> AsyncIterator[list[bytes | None]]:
    """Cut the body's chunks into lines, yielding the complete lines of each chunk as one batch.

    The same contract as stream.read_lines: a line longer than max_bytes comes out as None, and
    its bytes are dropped as they arrive, so the buffer never holds more than max_bytes plus
    one chunk, however long the line or the body is.
    """
    buffer = bytearray()  # the start of a line whose newline hasn't arrived yet
    skipping = False  # inside a too-long line that was already reported: drop until its newline
    async for chunk in chunks:
        batch: list[bytes | None] = []
        start = 0
        while (end := chunk.find(b"\n", start)) != -1:
            if skipping:
                skipping = False
            elif len(buffer) + end - start > max_bytes:
                batch.append(None)
            else:
                batch.append(bytes(buffer) + chunk[start:end + 1])
            buffer.clear()
            start = end + 1
        if not skipping:
            buffer += chunk[start:]
            if len(buffer) > max_bytes:
                batch.append(None)
                buffer.clear()
                skipping = True
        if batch:
            yield batch
    if buffer:
        yield [bytes(buffer)]  # a last line without a newline


class BodyStreamingResponse(StreamingResponse):
    """A StreamingResponse that can be sent while the request body is still being read.

    Starlette's own one (0.41) runs a disconnect listener next to the response, which calls
    receive() and throws away every message that isn't a disconnect. While we are still reading
    the body, those messages are body chunks: a client that uploads in pieces got back an empty
    response (tests/test_service.py reproduces it). Here only our own code reads the body. A
    client that disconnects is still noticed: request.stream() raises ClientDisconnect, which
    ends the response.
    """

    async def __call__(self, scope, receive, send) -> None:
        await self.stream_response(send)


def create_app(rules: Rules, max_line_bytes: int = DEFAULT_MAX_LINE_BYTES) -> FastAPI:
    # No /docs or /openapi.json: nothing in this service needs them, and less surface is safer.
    app = FastAPI(title="redactor", docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    @app.post("/redact")
    async def redact(request: Request):
        return BodyStreamingResponse(_redact_body(request.stream(), rules, max_line_bytes), media_type=NDJSON)

    return app


async def _redact_body(chunks: AsyncIterator[bytes], rules: Rules, max_line_bytes: int) -> AsyncIterator[bytes]:
    # A Redactor holds the counts of the line it is working on, so each request gets its own.
    # The compiled rules are shared: nothing changes them after loading.
    redactor = Redactor(rules)
    processor = LineProcessor(redactor, sys.stderr)
    try:
        async for batch in split_lines(chunks, max_line_bytes):
            # Redacting is CPU work. Done here, it would block the event loop, and with it every
            # other request and /healthz, for as long as the batch takes (long for a 1 MiB line).
            # In a worker thread, the loop stays free. Batches are awaited one at a time, so the
            # output keeps the input's order.
            out = await asyncio.to_thread(_process_batch, processor, batch)
            if out:
                yield out.encode("utf-8")
    finally:
        print(format_summary(redactor, processor.stats), file=sys.stderr)


def _process_batch(processor: LineProcessor, batch: list[bytes | None]) -> str:
    return "".join(line for raw in batch if (line := processor.process(raw)) is not None)


def parse_addr(addr: str) -> tuple[str, int]:
    """":8080" -> ("0.0.0.0", 8080), "127.0.0.1:9000" -> ("127.0.0.1", 9000)."""
    host, sep, port = addr.rpartition(":")
    if not sep or not port.isdigit() or not 0 < int(port) < 65536:
        raise ValueError(f"invalid address {addr!r}, expected [host]:port")
    return host or "0.0.0.0", int(port)


def serve(rules: Rules, addr: str, max_line_bytes: int) -> None:
    import uvicorn

    host, port = parse_addr(addr)
    uvicorn.run(
        create_app(rules, max_line_bytes),
        host=host,
        port=port,
        log_level="info",
        ws="none",  # no websockets: nothing here uses them
        # On SIGTERM (Kubernetes stopping the pod), stop accepting, let running requests finish
        # for up to 20 s, then close them. Kubernetes waits 30 s before it kills the process.
        timeout_graceful_shutdown=20,
    )
