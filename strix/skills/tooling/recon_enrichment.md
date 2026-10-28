---
name: recon-enrichment
description: Safe command patterns for passive-source enrichment, historical URLs, parameter mining, JavaScript analysis, and visual web triage
---

# Recon Enrichment Tooling

This is a command reference for the `web_attack_surface` workflow. Use only on
authorized assets and keep every active command bounded. Prefer JSONL or small
normalized files over retaining large raw crawls.

## Passive Sources

```bash
# Existing passive baseline
subfinder -d example.com -all -recursive -rl 20 -silent -o subs.txt

# Certificate transparency (free source; preserve raw response separately)
curl -s 'https://crt.sh/?q=%25.example.com&output=json' \
  | jq -r '.[].name_value' | sed 's/^\*\.//' | sort -u > ct-hosts.txt

# Optional sources, only when the engagement supplies credentials and permits
# the provider: GitHub subdomain search, VirusTotal, Shodan, OTX, urlscan.
```

Treat external API results as leads. Preserve `source`, query timestamp, and
scope decision; do not probe a third-party or sibling domain just because an API
returned it.

## Permutation and Resolution

```bash
# Generate only naming patterns derived from observed labels
cat observed-hosts.txt | alterx -silent | dnsx -silent -a -aaaa -cname -resp > resolved.txt
```

If `alterx`/`dnsx` is unavailable, use a small, target-derived list with `dig`
and record that the fallback has lower coverage. Do not substitute a massive
generic wordlist without an explicit scope and rate decision.

## ASN and Live Host Probing

```bash
asnmap -d example.com | dnsx -silent > asn-hosts.txt
cat hosts.txt | httpx -sc -title -server -td -tls-grab -favicon -json \
  -rl 50 -t 25 -timeout 10 -retries 1 -o httpx.jsonl
```

Use `naabu`/`nmap` for approved ports only. A shared cloud ASN or IP does not
establish target ownership; correlate with DNS, certificate, vhost, and scope
evidence.

## Historical URLs and Crawling

```bash
gau --subs example.com | sort -u > gau.txt
waybackurls example.com | sort -u > wayback.txt
cat live.txt | katana -d 3 -jc -kf robotstxt -ct 10m -mdp 2000 \
  -fsu -c 10 -p 10 -rl 50 -timeout 10 -retry 1 -f url -silent > crawl.txt
```

Merge current and historical URLs only after normalization. Never replay every
archived URL blindly; first group by host/path, remove static noise, and confirm
the route is in scope.

## Parameter Discovery

```bash
arjun -u https://example.com/api/search -m GET,POST \
  --stable -t 5 --timeout 10 --rate-limit 10 -oT arjun.txt

# Use patterns on normalized URLs, not raw unbounded crawler output
cat urls.txt | gf 'xss|sqli|ssrf|redirect|lfi' | sort -u > candidates.txt
```

Use ParamSpider/Kiterunner only when the endpoint and request volume are
authorized. Establish a normal response first and save status/length/body hash
so later differences are meaningful.

## JavaScript and Sensitive-File Triage

```bash
# First collect JS URLs; then analyze same-scope files only
grep -Ei '\.js([?#]|$)' urls.txt | sort -u > js.txt
cat js.txt | while read -r url; do curl -fsSL --max-time 10 "$url"; done \
  > js-bundle-snapshot.txt
rg -n -i '(/api/|graphql|wss?://|sourceMappingURL|token|secret|key)' \
  js-bundle-snapshot.txt

# Sensitive-file candidates (validate with the target and scope before testing)
grep -Ei '\.(env|log|sql|bak|zip|tar|gz|json|yaml|yml|map)([?#]|$)|/\.git/' \
  urls.txt | sort -u > sensitive-candidates.txt
```

Prefer JS-Snooper/jsniper, LinkFinder, or SecretFinder when installed. Redact
secrets in notes and route a confirmed disclosure to the appropriate specialist;
never use a found credential automatically.

## Content Discovery

Run the fixed dictionaries as separate jobs, with the aggregate target rate
kept within the agreed limit:

```bash
ffuf -u https://example.com/FUZZ \
  -w /workspace/wordlists/seclists-common.txt \
  -mc 200,204,301,302,307,401,403,405 -ac -t 20 -rate 50 \
  -timeout 10 -noninteractive -of json -o ffuf-common.json

ffuf -u https://example.com/FUZZ \
  -w /workspace/wordlists/dirsearch-dicc.txt \
  -mc 200,204,301,302,307,401,403,405 -ac -t 20 -rate 50 \
  -timeout 10 -noninteractive -of json -o ffuf-dirsearch.json
```

Normalize and combine results after both jobs finish. Do not concatenate the
lists into a Cartesian product and do not download replacement dictionaries.

## Technology and Visual Triage

```bash
# Optional WordPress-specific inventory, only for confirmed WordPress targets
wpscan --url https://example.com --enumerate ap,at,cb,dbe --plugins-detection passive

# Optional screenshots; prefer existing browser tooling if Aquatone is absent
cat live.txt | aquatone -ports 80,443,8080 -out screenshots
```

For TLS, use `httpx -tls-grab` first; use `sslyze`/`testssl.sh` only for a
focused, authorized TLS review. Screenshots and banners are triage evidence,
not proof of a vulnerability.

## Failure Recovery

- API source returns no data: record missing credentials/rate limiting; do not
  infer that the asset does not exist.
- Crawler volume grows: lower depth, page cap, response size, and duration;
  emit URL-only output.
- Parameter tool is noisy: lower concurrency/rate, use one endpoint, and
  compare against a saved baseline.
- Visual scanner is unavailable: use browser screenshots or skip visual triage;
  do not block the rest of recon.
- Tool output contains provider/CDN neighbors: stop active testing and rerun
  scope triage before continuing.
