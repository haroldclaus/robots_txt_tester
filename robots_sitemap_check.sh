#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"

SAMPLE_COUNT=20
POOL_SIZE=0          # 0 => auto (sample*50 capped)
POOL_MULT=50
POOL_MAX=5000
MATCH_UA="*"
FETCH_UA="OpenCodeRobotsSitemapCheck/1.0"
TIMEOUT_SECS=30
CONNECT_TIMEOUT_SECS=10
MAX_URLS=200000
MAX_SITEMAPS=200
MAX_DEPTH=2
LOG_LEVEL="INFO"   # DEBUG|INFO|WARN|ERROR

TMP_DIR=""

ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

_lvl_num() {
  case "$1" in
    DEBUG) echo 10 ;;
    INFO)  echo 20 ;;
    WARN)  echo 30 ;;
    ERROR) echo 40 ;;
    *)     echo 20 ;;
  esac
}

log() {
  local lvl="$1"; shift
  if (( $(_lvl_num "$lvl") < $(_lvl_num "$LOG_LEVEL") )); then
    return 0
  fi
  printf '%s [%s] %s\n' "$(ts)" "$lvl" "$*" >&2
}

die() {
  local msg="$1"
  local code="${2:-2}"
  log ERROR "$msg"
  exit "$code"
}

usage() {
  cat <<'EOF'
Usage:
  robots_sitemap_check.sh [options] <robots_txt_url>

Checks that 20 random URLs found in Sitemap(s) referenced by the given robots.txt
are allowed by that same robots.txt for a given user-agent.

Options:
  -n <count>        Sample size (default: 20)
  --pool-size <n>   Collect at least this many URLs before sampling (default: auto)
  -a <user-agent>   User-agent for robots.txt matching (default: *)
  --fetch-ua <ua>   User-agent used for HTTP fetching (default: OpenCodeRobotsSitemapCheck/1.0)
  --timeout <secs>  Curl max time in seconds (default: 30)
  --max-urls <n>    Cap URLs collected from sitemaps (default: 200000)
  --debug           Verbose logging
  -h, --help        Show help

Exit codes:
  0  Success (all sampled URLs are allowed)
  1  Validation failure (blocked URL(s), missing sitemaps/URLs)
  2  Usage / fetch / parsing / dependency error

Examples:
  ./robots_sitemap_check.sh https://example.com/robots.txt
  ./robots_sitemap_check.sh -a 'MyBot' -n 50 https://example.com/robots.txt
EOF
}

cleanup() {
  local code=$?
  if [[ -n "${TMP_DIR:-}" && -d "$TMP_DIR" ]]; then
    rm -rf "$TMP_DIR"
  fi
  return "$code"
}

trap cleanup EXIT

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing dependency: $1" 2
}

parse_args() {
  local arg
  while (($#)); do
    arg="$1"
    case "$arg" in
      -n)
        [[ ${2:-} =~ ^[0-9]+$ ]] || die "-n requires an integer" 2
        SAMPLE_COUNT="$2"; shift 2
        ;;
      --pool-size)
        [[ ${2:-} =~ ^[0-9]+$ ]] || die "--pool-size requires an integer" 2
        POOL_SIZE="$2"; shift 2
        ;;
      -a)
        [[ -n ${2:-} ]] || die "-a requires a value" 2
        MATCH_UA="$2"; shift 2
        ;;
      --fetch-ua)
        [[ -n ${2:-} ]] || die "--fetch-ua requires a value" 2
        FETCH_UA="$2"; shift 2
        ;;
      --timeout)
        [[ ${2:-} =~ ^[0-9]+$ ]] || die "--timeout requires an integer" 2
        TIMEOUT_SECS="$2"; shift 2
        ;;
      --max-urls)
        [[ ${2:-} =~ ^[0-9]+$ ]] || die "--max-urls requires an integer" 2
        MAX_URLS="$2"; shift 2
        ;;
      --debug)
        LOG_LEVEL="DEBUG"; shift
        ;;
      -h|--help)
        usage; exit 0
        ;;
      --)
        shift; break
        ;;
      -*)
        die "Unknown option: $arg" 2
        ;;
      *)
        break
        ;;
    esac
  done

  (( $# == 1 )) || { usage >&2; exit 2; }
  ROBOTS_URL="$1"

  (( SAMPLE_COUNT > 0 )) || die "-n must be > 0" 2
  (( MAX_URLS >= SAMPLE_COUNT )) || die "--max-urls must be >= sample size" 2
  (( POOL_SIZE >= 0 )) || die "--pool-size must be >= 0" 2
}

url_parse() {
  # Prints: scheme\thost\tpath_query
  local url="$1"
  url="${url%%#*}"
  if [[ "$url" =~ ^([a-zA-Z][a-zA-Z0-9+.-]*)://([^/]+)(/.*)?$ ]]; then
    local scheme="${BASH_REMATCH[1]}"
    local host="${BASH_REMATCH[2]}"
    local pathq="${BASH_REMATCH[3]:-/}"
    printf '%s\t%s\t%s\n' "$scheme" "$host" "$pathq"
    return 0
  fi
  return 1
}

url_origin() {
  local url="$1"
  local p
  p="$(url_parse "$url")" || return 1
  local scheme host
  scheme="${p%%$'\t'*}"
  host="${p#*$'\t'}"; host="${host%%$'\t'*}"
  printf '%s://%s\n' "$scheme" "$host"
}

resolve_url() {
  # Resolve relative/host-relative URLs against an origin.
  local origin="$1"
  local u="$2"

  if [[ "$u" =~ ^https?:// ]]; then
    printf '%s\n' "$u"
    return 0
  fi
  if [[ "$u" =~ ^// ]]; then
    # Protocol-relative.
    local scheme
    scheme="${origin%%://*}"
    printf '%s:%s\n' "$scheme" "$u"
    return 0
  fi
  if [[ "$u" =~ ^/ ]]; then
    printf '%s%s\n' "$origin" "$u"
    return 0
  fi
  if [[ -n "$u" ]]; then
    printf '%s/%s\n' "$origin" "$u"
    return 0
  fi
  return 1
}

curl_fetch_to_file() {
  local url="$1"
  local out="$2"

  log INFO "FETCH $url"

  if [[ ! "$url" =~ ^https?:// ]]; then
    return 1
  fi

  if [[ "$url" =~ \.gz($|\?) ]]; then
    need_cmd gzip
    if ! curl -fsSL --compressed --max-time "$TIMEOUT_SECS" --connect-timeout "$CONNECT_TIMEOUT_SECS" \
      -A "$FETCH_UA" "$url" | gzip -dc >"$out"; then
      return 1
    fi
  else
    if ! curl -fsSL --compressed --max-time "$TIMEOUT_SECS" --connect-timeout "$CONNECT_TIMEOUT_SECS" \
      -A "$FETCH_UA" "$url" >"$out"; then
      return 1
    fi
  fi
}

extract_sitemaps_from_robots() {
  local robots_file="$1"
  local out_file="$2"

  awk '
    function trim(s){ gsub(/^[ \t]+|[ \t]+$/,"",s); return s }
    {
      sub(/\r$/,"",$0)
      line=$0
      sub(/#.*/,"",line)
      line=trim(line)
      if (line=="") next
      pos=index(line,":")
      if (pos==0) next
      key=tolower(trim(substr(line,1,pos-1)))
      val=trim(substr(line,pos+1))
      if (key=="sitemap" && val!="") print val
    }
  ' "$robots_file" | awk '!seen[$0]++' >"$out_file"
}

parse_robots_rules_for_ua() {
  # Outputs matching rules (for the best UA match) as TSV:
  #   allow|disallow  <TAB>  pattern  <TAB>  length
  local robots_file="$1"
  local ua="$2"
  local out_rules="$3"
  local meta_file="$4"

  # shellcheck disable=SC2016
  awk -v our_ua="$ua" '
    function trim(s){ gsub(/^[ \t]+|[ \t]+$/,"",s); return s }
    BEGIN{
      group=0
      have_rules=0
      our=tolower(our_ua)
    }
    {
      sub(/\r$/,"",$0)
      line=$0
      sub(/#.*/,"",line)
      line=trim(line)
      if (line=="") next

      pos=index(line,":")
      if (pos==0) next
      key=tolower(trim(substr(line,1,pos-1)))
      val=trim(substr(line,pos+1))

      if (key=="user-agent") {
        if (have_rules) { group++; have_rules=0 }
        ua_n[group]++
        uas[group,ua_n[group]]=tolower(val)
        next
      }

      if (key=="allow" || key=="disallow") {
        have_rules=1
        # Empty Disallow means allow all.
        if (val=="") next
        rule_n++
        rule_type[rule_n]=key
        rule_pat[rule_n]=val
        rule_group[rule_n]=group
        rule_len[rule_n]=length(val)
        next
      }
    }
    END{
      maxlen=-1
      for (g=0; g<=group; g++) {
        best=-1
        for (i=1; i<=ua_n[g]; i++) {
          u=uas[g,i]
          if (u=="*") m=length(u)
          else if (index(our,u)==1) m=length(u)
          else m=-1
          if (m>best) best=m
        }
        group_match_len[g]=best
        if (best>maxlen) maxlen=best
      }

      print "match_len\t" maxlen > "/dev/stderr"
      if (maxlen<0) exit

      for (r=1; r<=rule_n; r++) {
        g=rule_group[r]
        if (group_match_len[g]==maxlen) {
          print rule_type[r] "\t" rule_pat[r] "\t" rule_len[r]
        }
      }
    }
  ' "$robots_file" 2>"$meta_file" >"$out_rules"
}

robots_pat_to_ere() {
  # Converts a robots pattern to an ERE suitable for bash [[ =~ ]].
  # - Anchors at start.
  # - Supports '*' wildcards.
  # - Supports '$' end anchor only when it is the last character.
  local pat="$1"
  local end_anchor="0"

  if [[ "$pat" == *'$' ]]; then
    end_anchor="1"
    pat="${pat%$}"
  fi

  awk -v s="$pat" -v end="$end_anchor" '
    BEGIN {
      meta="\\.^$|?+()[]{}"
      out="^"
      for (i=1; i<=length(s); i++) {
        c=substr(s,i,1)
        if (c=="*") {
          out=out ".*"
        } else if (index(meta,c)>0) {
          out=out "\\" c
        } else {
          out=out c
        }
      }
      if (end=="1") out=out "$"
      print out
    }
  '
}

robots_check_allowed() {
  # Args: path_query rules_file
  # Prints reason to stdout.
  local pathq="$1"
  local rules_file="$2"

  local best_len=-1
  local best_type=""
  local best_pat=""
  local best_re=""

  if [[ ! -s "$rules_file" ]]; then
    printf 'ALLOW (no applicable rules)\n'
    return 0
  fi

  while IFS=$'\t' read -r type pat len; do
    [[ -n "$type" && -n "$pat" ]] || continue
    local re
    re="$(robots_pat_to_ere "$pat")"
    if [[ "$pathq" =~ $re ]]; then
      if (( len > best_len )); then
        best_len="$len"; best_type="$type"; best_pat="$pat"; best_re="$re"
      elif (( len == best_len )) && [[ "$best_type" == "disallow" && "$type" == "allow" ]]; then
        best_len="$len"; best_type="$type"; best_pat="$pat"; best_re="$re"
      fi
    fi
  done <"$rules_file"

  if [[ -z "$best_type" ]]; then
    printf 'ALLOW (no matching rule)\n'
    return 0
  fi

  if [[ "$best_type" == "disallow" ]]; then
    printf 'BLOCK (matched disallow pattern=%q len=%s regex=%q)\n' "$best_pat" "$best_len" "$best_re"
    return 1
  fi

  printf 'ALLOW (matched allow pattern=%q len=%s regex=%q)\n' "$best_pat" "$best_len" "$best_re"
  return 0
}

is_xml_sitemap() {
  local file="$1"
  # A cheap heuristic: if it contains <urlset> or <sitemapindex>
  grep -Eqi '<(urlset|sitemapindex)([[:space:]]|>)' "$file"
}

is_sitemap_index() {
  local file="$1"
  grep -Eqi '<sitemapindex([[:space:]]|>)' "$file"
}

extract_locs_from_xml() {
  local file="$1"
  # Streaming-ish extraction of <loc>...</loc>.
  awk '
    BEGIN{RS="<loc>"; FS="</loc>"}
    NR>1 {
      loc=$1
      gsub(/<!\[CDATA\[/,"",loc)
      gsub(/\]\]>/,"",loc)
      gsub(/^[ \t\r\n]+|[ \t\r\n]+$/,"",loc)
      if (loc!="") print loc
    }
  ' "$file"
}

extract_urls_from_sitemap_file() {
  # Prints URLs (absolute or relative) from a sitemap file.
  local file="$1"
  if is_xml_sitemap "$file"; then
    extract_locs_from_xml "$file"
  else
    # Plaintext sitemap: one URL per line.
    awk '{sub(/\r$/,"",$0); gsub(/^[ \t]+|[ \t]+$/,"",$0); if ($0!="") print $0}' "$file"
  fi
}

main() {
  parse_args "$@"

  need_cmd curl
  need_cmd awk
  need_cmd grep
  need_cmd wc
  need_cmd sed
  need_cmd tr

  TMP_DIR="$(mktemp -d)"

  log INFO "robots_url=$ROBOTS_URL"
  log INFO "match_user_agent=$MATCH_UA"
  log INFO "sample_count=$SAMPLE_COUNT"
  log INFO "max_urls=$MAX_URLS"

  local desired_pool
  if (( POOL_SIZE > 0 )); then
    desired_pool="$POOL_SIZE"
  else
    desired_pool=$(( SAMPLE_COUNT * POOL_MULT ))
    if (( desired_pool < SAMPLE_COUNT )); then desired_pool="$SAMPLE_COUNT"; fi
    if (( desired_pool > POOL_MAX )); then desired_pool="$POOL_MAX"; fi
  fi
  if (( desired_pool > MAX_URLS )); then desired_pool="$MAX_URLS"; fi
  log INFO "pool_target=$desired_pool"

  local robots_origin_val
  robots_origin_val="$(url_origin "$ROBOTS_URL")" || die "robots_txt_url must be an absolute http(s) URL" 2

  local parsed
  parsed="$(url_parse "$ROBOTS_URL")" || die "robots_txt_url must be an absolute http(s) URL" 2
  local robots_scheme robots_host
  robots_scheme="${parsed%%$'\t'*}"
  if [[ ! "$robots_scheme" =~ ^https?$ ]]; then
    die "robots_txt_url must be an absolute http(s) URL" 2
  fi
  local rem="${parsed#*$'\t'}"
  robots_host="${rem%%$'\t'*}"
  local robots_host_lc
  robots_host_lc="$(printf '%s' "$robots_host" | tr '[:upper:]' '[:lower:]')"

  local robots_file="$TMP_DIR/robots.txt"
  if ! curl_fetch_to_file "$ROBOTS_URL" "$robots_file"; then
    die "Failed to fetch robots.txt: $ROBOTS_URL" 2
  fi
  log INFO "robots_fetched_bytes=$(wc -c <"$robots_file" | tr -d ' ')"

  local sitemaps_file="$TMP_DIR/sitemaps.txt"
  extract_sitemaps_from_robots "$robots_file" "$sitemaps_file"
  local sitemap_count
  sitemap_count="$(wc -l <"$sitemaps_file" | tr -d ' ')"
  if (( sitemap_count == 0 )); then
    die "No Sitemap entries found in robots.txt" 1
  fi
  log INFO "sitemaps_found=$sitemap_count"

  local rules_file="$TMP_DIR/rules.tsv"
  local meta_file="$TMP_DIR/rules.meta"
  parse_robots_rules_for_ua "$robots_file" "$MATCH_UA" "$rules_file" "$meta_file"
  local match_len
  match_len="$(awk -F'\t' '$1=="match_len"{print $2}' "$meta_file" 2>/dev/null || true)"
  if [[ -z "$match_len" ]]; then
    match_len="-1"
  fi
  log INFO "robots_group_match_len=$match_len"
  log INFO "robots_rules_selected=$(wc -l <"$rules_file" | tr -d ' ')"

  local urls_raw="$TMP_DIR/urls.raw"
  : >"$urls_raw"
  local urls_added=0
  local sitemaps_seen=0

  declare -A SEEN_SITEMAP
  declare -A SEEN_URL

  parse_sitemap_url() {
    local sitemap_url="$1"
    local depth="$2"

    if (( urls_added >= desired_pool || urls_added >= MAX_URLS )); then
      return 0
    fi
    if (( depth > MAX_DEPTH )); then
      log WARN "Skip sitemap (max depth reached): $sitemap_url"
      return 0
    fi
    if [[ -n "${SEEN_SITEMAP[$sitemap_url]:-}" ]]; then
      log DEBUG "Skip sitemap (already seen): $sitemap_url"
      return 0
    fi
    SEEN_SITEMAP[$sitemap_url]=1
    sitemaps_seen=$((sitemaps_seen+1))
    if (( sitemaps_seen > MAX_SITEMAPS )); then
      log WARN "Stop sitemap traversal (MAX_SITEMAPS=$MAX_SITEMAPS reached)"
      return 0
    fi

    local sm_file="$TMP_DIR/sitemap.$sitemaps_seen"
    if ! curl_fetch_to_file "$sitemap_url" "$sm_file"; then
      log WARN "Failed to fetch sitemap: $sitemap_url"
      return 0
    fi

    if is_xml_sitemap "$sm_file" && is_sitemap_index "$sm_file"; then
      log INFO "sitemap_index depth=$depth url=$sitemap_url"
      local child_count=0
      while IFS= read -r child; do
        child="$(printf '%s' "$child" | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')"
        [[ -n "$child" ]] || continue
        child_count=$((child_count+1))
        local child_abs
        child_abs="$(resolve_url "$robots_origin_val" "$child" 2>/dev/null || true)"
        if [[ -z "$child_abs" ]]; then
          log DEBUG "Skip child sitemap (unresolvable): $child"
          continue
        fi
        parse_sitemap_url "$child_abs" $((depth+1))
        if (( urls_added >= desired_pool || urls_added >= MAX_URLS )); then
          break
        fi
      done < <(extract_urls_from_sitemap_file "$sm_file")
      log INFO "sitemap_index_children=$child_count url=$sitemap_url"
      return 0
    fi

    log INFO "sitemap_urlset depth=$depth url=$sitemap_url"

    while IFS= read -r u; do
      if (( urls_added >= desired_pool )); then
        log INFO "Pool target reached; stopping URL collection"
        break
      fi
      if (( urls_added >= MAX_URLS )); then
        log WARN "URL cap reached (MAX_URLS=$MAX_URLS); stopping URL collection"
        break
      fi

      u="$(printf '%s' "$u" | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')"
      [[ -n "$u" ]] || continue

      local abs
      abs="$(resolve_url "$robots_origin_val" "$u" 2>/dev/null || true)"
      if [[ -z "$abs" ]]; then
        log DEBUG "Skip URL (unresolvable): $u"
        continue
      fi

      local up
      up="$(url_parse "$abs" 2>/dev/null || true)"
      if [[ -z "$up" ]]; then
        log DEBUG "Skip URL (not absolute http(s)): $abs"
        continue
      fi

      local host
      host="${up#*$'\t'}"; host="${host%%$'\t'*}"
      host="$(printf '%s' "$host" | tr '[:upper:]' '[:lower:]')"
      if [[ "$host" != "$robots_host_lc" ]]; then
        log DEBUG "Skip URL (different host): $abs"
        continue
      fi

      if [[ -n "${SEEN_URL[$abs]:-}" ]]; then
        continue
      fi
      SEEN_URL[$abs]=1
      printf '%s\n' "$abs" >>"$urls_raw"
      urls_added=$((urls_added+1))
    done < <(extract_urls_from_sitemap_file "$sm_file")
  }

  while IFS= read -r sm; do
    sm="$(printf '%s' "$sm" | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')"
    [[ -n "$sm" ]] || continue
    local sm_abs
    sm_abs="$(resolve_url "$robots_origin_val" "$sm" 2>/dev/null || true)"
    if [[ -z "$sm_abs" ]]; then
      log WARN "Skip sitemap (unresolvable): $sm"
      continue
    fi
    parse_sitemap_url "$sm_abs" 0
    if (( urls_added >= desired_pool || urls_added >= MAX_URLS )); then
      break
    fi
  done <"$sitemaps_file"

  if (( urls_added == 0 )); then
    die "No URLs extracted from sitemap(s)" 1
  fi
  log INFO "urls_collected_unique=$urls_added"

  if (( urls_added < SAMPLE_COUNT )); then
    die "Not enough URLs to sample: have=$urls_added need=$SAMPLE_COUNT" 1
  fi

  need_cmd shuf
  local sample_file="$TMP_DIR/sample.txt"
  shuf -n "$SAMPLE_COUNT" "$urls_raw" >"$sample_file"
  log INFO "sampled_urls=$SAMPLE_COUNT"

  local failures=0
  local checked=0

  while IFS= read -r full_url; do
    checked=$((checked+1))
    local p
    p="$(url_parse "$full_url")" || { log WARN "Skip sampled URL (parse failed): $full_url"; continue; }
    local pathq
    pathq="${p##*$'\t'}"

    local reason
    if reason="$(robots_check_allowed "$pathq" "$rules_file")"; then
      log INFO "ALLOW url=$full_url path=$pathq reason=$reason"
    else
      log ERROR "BLOCK url=$full_url path=$pathq reason=$reason"
      failures=$((failures+1))
    fi
  done <"$sample_file"

  if (( failures > 0 )); then
    die "Validation failed: blocked_urls=$failures sampled=$SAMPLE_COUNT" 1
  fi

  log INFO "Validation OK: all_sampled_urls_allowed sampled=$SAMPLE_COUNT"
}

main "$@"
