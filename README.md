# nginx-audit

nginx-audit parses nginx configuration (tokens, quoting, comments, nested blocks) and checks it against a short list of well known problems: obsolete TLS versions and weak ciphers, `alias` paths that allow directory traversal, `autoindex`, version disclosure, an exposed `stub_status`, disabled upstream certificate checks, and TLS servers without HSTS. Findings carry the file and line.

**Live demo:** https://jvch0512.github.io/nginx-audit/ (Synthetic configs, not from a real host.)

Ruby 3, standard library only. The demo page is rendered from the tool's `--tsv` output by `scripts/site.py` (Python 3, only needed to regenerate the page).

## Use

```bash
ruby bin/nginx-audit examples/configs
ruby bin/nginx-audit /etc/nginx/nginx.conf --tsv
ruby bin/nginx-audit ./conf.d --fail-on high        # exit 1 if any high finding
```

Pass a file or a directory (all `*.conf` files, recursively).

| Rule | Severity | What it catches |
|---|---|---|
| NGX001 | medium | `autoindex on`: directory listings |
| NGX002 | medium or low | `server_tokens on` (medium); not set at all in `http` (low) |
| NGX003 | high | `ssl_protocols` allows SSLv2, SSLv3, TLSv1 or TLSv1.1 |
| NGX004 | high | `ssl_ciphers` allows RC4, DES, 3DES, MD5, NULL, EXPORT or aNULL |
| NGX005 | medium | a TLS server without `Strict-Transport-Security` |
| NGX006 | high | `location /x { alias /y/; }`: the missing slash lets `/x../` walk out of the directory |
| NGX007 | low | `client_max_body_size 0`: no upload limit |
| NGX008 | low | a TLS server without `X-Content-Type-Options` |
| NGX009 | medium | `stub_status` without `allow` and `deny` |
| NGX010 | medium | `proxy_ssl_verify off` |
| NGX000 | info | syntax problem: unbalanced braces or unterminated quote |

See [examples](examples) and [docs/sample-output.txt](docs/sample-output.txt).

## Limits

- `include` is not followed. Audit the files that you include as well, or concatenate them first (`nginx -T` prints the full effective config).
- Inheritance is approximated: `add_header` set in a parent block counts for its children, which is not how nginx behaves when a child defines its own `add_header`.
- Directives inside `if` blocks and `map` values are parsed but not interpreted.
- It reads text, it does not run nginx. Use `nginx -t` for syntax and module checks.

## Where it fits

Web hosting, platform and security review: a quick pre-merge gate for config changes and a first pass in a hardening engagement.

## Tests

```bash
make test    # minitest unit tests: parser (quoting, comments, nesting, errors), every rule on good and bad input, and CLI exit codes
```

MIT.
