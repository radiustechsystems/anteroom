# hello-app

A small demonstration web service. One binary, no dependencies beyond the Go
standard library, no database, no state.

## Running it

```sh
docker compose up --build      # http://localhost:3000
```

Or without Docker:

```sh
go run .                       # honours HELLO_LISTEN, default :3000
```

## Routes

| Path | What it serves |
| --- | --- |
| `/` | an HTML document |
| `/about` | a second HTML document |
| `/api/items` | JSON |
| `/static/*` | static assets (CSS, a compressible text file) |
| `/robots.txt`, `/sitemap.xml` | crawler files |
| `/feed.xml` | an RSS feed |
| `/webhooks/inbound` | accepts a POST and echoes the body back |
| `/events` | a server-sent event stream (five ticks) |
| `/download/big.bin` | an 8 MB deterministic download |
| `/csp/{none,self,unsafe-inline,strict-dynamic,hash,none-directive,sandbox,host-allowlist,report-only,meta}` | one page per Content-Security-Policy shape |
| `/sw-owner`, `/sw.js` | a page registering a root-scoped service worker with a catch-all fetch handler |
| `/slow` | responds after 30 seconds |
| `/set-cookie` | sets two cookies of its own |
| `/echo` | reflects the method, path, host, and every header it received, as JSON |
| `/healthz` | liveness |

`/echo` is the useful one when something sits in front of this app: it reports
exactly what arrived, so you can see what was added, removed, or rewritten.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `HELLO_LISTEN` | `:3000` | bind address |
