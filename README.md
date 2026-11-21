# firecrawl-local-guard-audit

Firecrawl Local refuses private-network targets, but it never tells you *which* targets are protected by the URL check and which are protected only by DNS. This tool answers that offline, before you point an agent at a page it should not reach.

Upstream: https://github.com/firecrawl/firecrawl

## Why now

Firecrawl Local (`apps/local`) ships a two-stage private-network guard: `guard::check_url` inspects the URL before any request, and a custom `GuardedResolver` filters the addresses DNS returns at connect time. The README promises that link-local and cloud metadata addresses are blocked "in every mode, including after redirects and DNS resolution" ([README Security](https://github.com/firecrawl/firecrawl/blob/main/apps/local/README.md#L186-L196)).

The split has a consequence the docs do not spell out: for any hostname that is not an IP literal or a static local name, `check_url` returns `Ok(())` and the entire refusal decision moves to the resolver ([guard.rs#L161-L173](https://github.com/firecrawl/firecrawl/blob/main/apps/local/src/guard.rs#L161-L173)). `Fetcher::new` attaches that resolver but never calls `.no_proxy()` ([fetch.rs#L185-L193](https://github.com/firecrawl/firecrawl/blob/main/apps/local/src/fetch.rs#L185-L193)), so reqwest honours `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` and hands the URL to the proxy: the resolver never sees the target. That is exactly the bypass reported in [issue #5942](https://github.com/firecrawl/firecrawl/issues/5942).

The API layer has a second, independent failure: a refused private target can come back as `success: true` with `metadata.statusCode: 403` and no content ([issue #5897](https://github.com/firecrawl/firecrawl/issues/5897)), so clients that trust `success` see an empty success. The repository's own test asserts that shape, which is why it cannot be caught from inside.

## What it does

Two offline subcommands, zero dependencies, no network:

- `targets` — takes a list of URLs and reproduces `guard.rs` exactly (scheme, credentials, IPv4/IPv6 classifier including CGNAT, benchmarking, documentation, `240/4`, NAT64 and IPv4-mapped forms, the static local-name list, and the Alibaba metadata special case). Each URL is labelled `blocked` (with the rule that fires) or `ok`. Every `ok` hostname that is not an IP literal is marked `dns_gate_only`, because only the resolver can refuse it. If a proxy variable is present (from the environment or `--proxy-var`), those entries become `PROXY_BYPASS_RISK`.
- `responses` — reads saved `/v2/scrape` JSON and flags `MISREPORTED_REFUSAL` (a guard refusal reported as `success: true` with `statusCode: 403`) and `SUCCESS_WITHOUT_CONTENT`.

It does **not** resolve DNS, contact Firecrawl, or decide whether a hostname currently points at a private address. It tells you which decisions are still open at that point, which is the part you cannot see from the outside.

## Install

Python 3.8+, standard library only. No install step:

```bash
git clone git@github-linmoxi33:linmoxi33/firecrawl-local-guard-audit.git
cd firecrawl-local-guard-audit
python3 bin/firecrawl-local-guard-audit targets examples/in/targets.txt --json
```

## Usage

```bash
# Which targets will be refused before any network activity?
python3 bin/firecrawl-local-guard-audit targets targets.txt

# Same list, but with a proxy configured (the #5942 bypass class)
python3 bin/firecrawl-local-guard-audit targets targets.txt --proxy-var HTTPS_PROXY

# Local CLI/MCP against your own intranet: private ranges are permitted,
# link-local and metadata addresses are still refused.
python3 bin/firecrawl-local-guard-audit targets targets.txt --policy allow-private

# Triage saved scrape responses
python3 bin/firecrawl-local-guard-audit responses examples/in/responses/*.json --json
```

`--json` prints a deterministic report (sorted keys, no timestamps); `--out FILE` writes the same object to disk.

```json
{
  "mode": "targets",
  "policy": "public-only",
  "proxy_vars": ["HTTPS_PROXY"],
  "summary": {"blocked": 3, "dns_gate_only": 2, "proxy_bypass_risk": 2, "targets": 5},
  "findings": [
    {"id": "PROXY_BYPASS_RISK", "severity": "error", "line": 8,
     "url": "https://internal-gateway.example.com/health", "rule": "DNS_RESOLVER_ONLY"}
  ]
}
```

Exit codes:

| code | meaning |
| --- | --- |
| 0 | no warning or error findings |
| 1 | at least one `warning` (a target will be refused) or `error` (proxy bypass risk, misreported refusal) |
| 2 | usage error, missing file, or unparseable JSON |

`DNS_GATE_ONLY` and `REFUSAL_REPORTED` are `info` and do not change the exit code.

## Limits

- No DNS: a hostname's current answer is never inspected. `dns_gate_only` means "the guard has not decided yet", not "this host is private".
- The port is a line-by-line translation of `guard.rs` at `main` (2026-11-21) and is checked against the upstream's own `#[cfg(test)]` vectors; if upstream changes the classifier, this tool must be updated.
- Proxy detection is an environment/flag heuristic. It reports the bypass class; it does not prove a specific request used a proxy.
- The responses mode recognises the documented refusal shape; other error shapes are reported as ordinary records.
- Not affiliated with Firecrawl.

## 本轮创新

首个把 Firecrawl Local 私有网络守卫的判定拆成「URL 静态层」与「DNS 解析层」两段，并指出只有 IP 字面量和静态本地名在 URL 层就被拒，其余主机名的安全性完全挂在解析器上——也就是 #5942 里代理环境变量绕过的那一类；同时对保存的抓取响应区分「真的成功」与「拒绝被报成 success:true」（#5897）。同一份判定表用上游自己的 Rust 测试向量做 oracle（19 tests 中的 6 个直接复用这些向量），不是复述 README。

## License

MIT. See [LICENSE](LICENSE).
