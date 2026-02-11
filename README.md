# robots_txt_tester

CLI script that fetches a `robots.txt`, discovers `Sitemap:` entries, samples URLs from those sitemap(s), and checks whether the sampled URLs are allowed for a given user-agent.

## Run

- `chmod +x robots_sitemap_check.sh`
- `./robots_sitemap_check.sh --debug https://www.example.com/robots.txt`

## Useful options

- `-n 20` sample size
- `-a 'MyBot'` user-agent to evaluate robots rules
- `--pool-size 1000` how many URLs to collect before sampling
- `--timeout 30` curl max-time per request
- `--debug` verbose logging

## Requirements

- Bash 4+
- `curl`, `awk`, `grep`, `wc`, `sed`, `tr`, `shuf` (and `gzip` for `.gz` sitemaps)
