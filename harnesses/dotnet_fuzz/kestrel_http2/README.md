# Kestrel structured HTTP/2 lane

This loopback-only lane maps bounded decision bytes onto HTTP/2 frame sequences while preserving
enough grammar to reach Kestrel's stream and flow-control state machines. It covers
HEADERS/CONTINUATION boundaries, DATA lengths and padding, trailers, stream lifecycle,
SETTINGS/WINDOW_UPDATE boundaries, multiple streams, and a fixed victim request.

Each input is delivered both contiguously and across frame/header/payload cuts. The harness
compares complete response-stream outcomes and verifies application markers for valid scenarios.
Timeouts and ordinary protocol rejections are coverage classes, not crash oracles. Kestrel itself
remains uninstrumented; SharpFuzz instruments only `KestrelHttp2Fuzz.Http2OutcomeCoverage`.

Run `./campaign.sh prepare`, then `./campaign.sh replay-seeds` for clean controls. Run
`./campaign.sh start` to create the append-only `afl-structured-v1` campaign beneath
`workspace/dotnet-bounty/kestrel-http2-structured/`.
