# Browser Dialer download backpressure measurement

The normal regression tests need only Go and Node.js:

```sh
go test -race ./transport/internet/browser_dialer ./transport/internet/splithttp
node --test transport/internet/browser_dialer/dialer_test.mjs
```

`go test` also invokes the page tests if `node` is on PATH; otherwise that test
is explicitly skipped. No npm packages are needed for these regression tests.

This optional harness measures the real page in Chromium against a local TLS
HTTP/2 server. It uses `DialGetStream` to receive data, holds the application
reader for three seconds, and either closes it (`stall`) or resumes it (`resume`).
`fast` reads immediately. Both successful-transfer modes verify every byte using
SHA-256. No proxy server, account, or external test traffic is needed.

From the repository root, with Go 1.27 and Node.js 24 available:

```sh
test_dir=$(mktemp -d)
go build -o "$test_dir/server" ./transport/internet/browser_dialer/testdata/backpressure/server.go
npm install --prefix "$test_dir" playwright@1.62.1
export PLAYWRIGHT_BROWSERS_PATH="$test_dir/browsers"
node "$test_dir/node_modules/playwright/cli.js" install chromium
export XRAY_PLAYWRIGHT_MODULE="$test_dir/node_modules/playwright"
export XRAY_BROWSER_TEST_SERVER="$test_dir/server"

node transport/internet/browser_dialer/testdata/backpressure/run.cjs \
  transport/internet/browser_dialer/dialer.html stall
node transport/internet/browser_dialer/testdata/backpressure/run.cjs \
  transport/internet/browser_dialer/dialer.html resume
node transport/internet/browser_dialer/testdata/backpressure/run.cjs \
  transport/internet/browser_dialer/dialer.html fast
```

Alternatively, set `XRAY_BROWSER_TEST_EXECUTABLE` to an existing Chromium/Chrome
executable and omit the browser installation. The measured version is emitted in
the output. A final size argument sets the response size in bytes (default: 256 MiB).

To compare the original transport, save its page and select the retained raw
`DialGet` / `websocket.NewConnection` reader, as used by main before this change:

```sh
git show 61cad5ec8b692692c08aee21cb8c756bdb7da13c:transport/internet/browser_dialer/dialer.html > "$test_dir/baseline.html"
XRAY_BROWSER_TEST_LEGACY=1 node transport/internet/browser_dialer/testdata/backpressure/run.cjs \
  "$test_dir/baseline.html" stall
XRAY_BROWSER_TEST_LEGACY=1 node transport/internet/browser_dialer/testdata/backpressure/run.cjs \
  "$test_dir/baseline.html" fast
```

`wireBytes` counts successful writes to the origin's TCP sockets, including TLS
records and handshakes but excluding TCP/IP headers and retransmissions.
`bodyBytes` counts response bytes accepted by the HTTP server. Browser queue
samples are separate: HTTP/2 flow control and browser/OS buffers allow read-ahead
beyond the 4 MiB application window. `stall` should reach a plateau rather than
consume the entire response. The byte bound is window plus one browser chunk,
not a bound on all browser memory or on total TCP bytes in flight.

`elapsedMs` runs from observing the GET to observing completion, with 20 ms
sampling granularity. For `resume` it includes the initial three-second pause.
Run several `fast` trials on an otherwise idle machine; these are local throughput
controls, not WAN benchmarks or evidence of resistance to a particular DPI system.
The harness measures a visible headless page; the unit test separately rejects
any use of polling timers in the download loop.
