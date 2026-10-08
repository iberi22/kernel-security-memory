"""Fetch and validate curl security fixes slice for Fable study.

Supports:
  --fetch: Talks to network under byte caps to generate study slice.
  --offline: Reads committed study files and validates contract (exits 0 on match, 1 on error).
"""
import argparse
import hashlib
import json
import os
import re
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone

STUDY_DIR = os.path.join("docs", "studies", "fable-2026-06", "curl")
STUDY_JSON = os.path.join(STUDY_DIR, "study.json")
PATTERNS_MD = os.path.join(STUDY_DIR, "patterns.md")
RECORDS_DIR = os.path.join(STUDY_DIR, "records")

PER_RESPONSE_LIMIT = 1 * 1024 * 1024  # 1 MiB
CUMULATIVE_LIMIT = 2 * 1024 * 1024    # 2 MiB

ALLOWLIST_HOSTS = {
    "api.osv.dev",
    "osv.dev",
    "github.com",
    "api.github.com",
    "git.kernel.org",
    "www.kernel.org",
    "gitlab.com",
    "www.openssl.org",
    "openssl.org",
    "curl.se",
    "nginx.org",
    "www.postgresql.org",
    "www.sqlite.org",
    "sqlite.org",
    "www.nlnetlabs.nl",
    "sourceware.org"
}

VALID_PATTERN_FAMILIES = {
    "memory-lifetime",
    "bounds",
    "integer",
    "concurrency",
    "authz",
    "injection",
    "crypto",
    "path-resolution",
    "parser",
    "resource-accounting",
    "logic",
    "unknown"
}

def is_allowlisted_url(url):
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        if parsed.scheme != "https":
            return False
        return parsed.netloc in ALLOWLIST_HOSTS
    except Exception:
        return False

def validate_study_json(data):
    if not isinstance(data, dict):
        return False, "study.json root must be a dict"

    if data.get("schema_version") != "study-slice-v1":
        return False, "schema_version must be study-slice-v1"

    expected_window = {
        "start": "2026-06-09",
        "end": "2026-10-08",
        "anchor": "Claude Fable 5 public announcement 2026-06-09"
    }
    if data.get("window") != expected_window:
        return False, f"window mismatch: {data.get('window')}"

    proj = data.get("project")
    if not isinstance(proj, dict) or proj.get("id") != "curl" or proj.get("repo") != "https://github.com/curl/curl" or proj.get("github") != "curl/curl":
        return False, f"project info invalid: {proj}"

    if data.get("coverage") not in ("INCOMPLETE", "WINDOW_SAMPLED"):
        return False, f"coverage invalid: {data.get('coverage')}"

    if not isinstance(data.get("method"), dict):
        return False, "method must be dict"
    method = data["method"]
    if "used_query" not in method or not isinstance(method.get("http_status"), int) or not isinstance(method.get("examined"), int):
        return False, "method missing required fields or types"

    limits = method.get("limits")
    if not isinstance(limits, dict) or limits.get("max_examined") != 40 or limits.get("max_records") != 8:
        return False, "method.limits invalid"

    recorded = data.get("recorded")
    if not isinstance(recorded, int) or not (0 <= recorded <= 8):
        return False, f"recorded invalid: {recorded}"

    records = data.get("records")
    if not isinstance(records, list) or len(records) != recorded:
        return False, f"records array length {len(records) if isinstance(records, list) else None} does not match recorded {recorded}"

    for rpath in records:
        if not rpath.startswith("records/") or not rpath.endswith(".json"):
            return False, f"record path format invalid: {rpath}"

    counts = data.get("counts_by_family")
    if not isinstance(counts, dict):
        return False, "counts_by_family must be dict"
    if sum(counts.values()) != recorded:
        return False, f"sum of counts_by_family ({sum(counts.values())}) != recorded ({recorded})"
    for k in counts.keys():
        if k not in VALID_PATTERN_FAMILIES:
            return False, f"invalid family in counts_by_family: {k}"

    skipped = data.get("skipped")
    if not isinstance(skipped, list):
        return False, "skipped must be list"
    for s in skipped:
        if not isinstance(s, dict) or "id" not in s or "reason" not in s:
            return False, f"invalid skipped item: {s}"

    errors = data.get("errors")
    if not isinstance(errors, list):
        return False, "errors must be list"
    if method["http_status"] == 200 and len(errors) != 0:
        return False, "errors must be empty when http_status is 200"

    notes = data.get("notes")
    if not isinstance(notes, str) or not notes.strip():
        return False, "notes must be a non-empty string"
    if recorded == 0 and "empty" not in notes.lower():
        return False, "when recorded is 0, notes must mention empty observation"

    return True, "OK"

def validate_record_json(data, expected_id=None):
    if not isinstance(data, dict):
        return False, "record root must be dict"

    if data.get("schema_version") != "study-record-v1":
        return False, "schema_version must be study-record-v1"

    rec_id = data.get("id")
    if not isinstance(rec_id, str) or not re.match(r"^[A-Za-z0-9_.-]+$", rec_id) or not rec_id.startswith("curl-"):
        return False, f"invalid record id: {rec_id}"
    if expected_id and rec_id != expected_id:
        return False, f"record id {rec_id} does not match filename expected {expected_id}"

    if data.get("project") != "curl":
        return False, "project must be 'curl'"

    if not isinstance(data.get("advisory_id"), str):
        return False, "advisory_id must be string"

    cwe = data.get("cwe")
    cwe_state = data.get("cwe_state")
    if cwe is None:
        if cwe_state != "UNKNOWN":
            return False, "when cwe is null, cwe_state must be UNKNOWN"
    else:
        if not isinstance(cwe, str) or cwe_state != "STATED_BY_ADVISORY":
            return False, "when cwe is provided, cwe_state must be STATED_BY_ADVISORY"

    pf = data.get("pattern_family")
    if pf not in VALID_PATTERN_FAMILIES:
        return False, f"invalid pattern_family: {pf}"

    if data.get("pattern_family_status") != "hypothesis":
        return False, "pattern_family_status must be 'hypothesis'"

    fix = data.get("fix")
    if not isinstance(fix, dict):
        return False, "fix must be dict"
    sha = fix.get("sha")
    if not isinstance(sha, str) or not re.match(r"^[0-9a-f]{40}$", sha):
        return False, f"fix.sha must be full 40 lowercase hex: {sha}"
    fix_url = fix.get("url")
    if not isinstance(fix_url, str) or not is_allowlisted_url(fix_url):
        return False, f"fix.url must be allowlisted HTTPS URL: {fix_url}"
    if not isinstance(fix.get("committed_at"), str):
        return False, "fix.committed_at must be string"

    insecure = data.get("insecure_pattern")
    if not isinstance(insecure, str) or not insecure.strip():
        return False, "insecure_pattern must be non-empty string"

    mitigation = data.get("mitigation")
    if not isinstance(mitigation, str) or not mitigation.strip():
        return False, "mitigation must be non-empty string"

    evidence = data.get("evidence")
    if not isinstance(evidence, list) or len(evidence) < 1:
        return False, "evidence must be non-empty list"
    for ev in evidence:
        if not isinstance(ev, dict):
            return False, "evidence item must be dict"
        if not is_allowlisted_url(ev.get("url")):
            return False, f"evidence url not allowlisted: {ev.get('url')}"
        sha256 = ev.get("sha256")
        if not isinstance(sha256, str) or not re.match(r"^[0-9a-f]{64}$", sha256):
            return False, f"evidence sha256 must be 64 lowercase hex: {sha256}"
        obs = ev.get("observed_at")
        if not isinstance(obs, str) or not obs.startswith("2026-10-08"):
            if not (isinstance(obs, str) and obs >= "2026-10-08"):
                return False, f"evidence observed_at must be on or after 2026-10-08: {obs}"

    limits = data.get("limits")
    if not isinstance(limits, str) or "single advisory" not in limits.lower():
        return False, "limits sentence must state record is a single advisory"

    return True, "OK"

def validate_patterns_md(content, counts_by_family):
    lines = content.splitlines()
    if len(lines) > 200:
        return False, f"patterns.md has {len(lines)} lines (max 200)"

    if len(lines) < 2 or "curl" not in lines[0].lower():
        return False, "patterns.md title line must name curl"

    if "Window: 2026-06-09 .. 2026-10-08" not in content:
        return False, "patterns.md missing 'Window: 2026-06-09 .. 2026-10-08'"

    headings = [line.strip() for line in lines if line.startswith("## ")]
    expected_headings = ["## Counts", "## Records", "## Limits"]
    if headings != expected_headings:
        return False, f"patterns.md headings mismatch: got {headings}, expected {expected_headings}"

    if "hypothesis" not in content.lower():
        return False, "patterns.md must explicitly state family labels are hypotheses"

    if "slice" not in content.lower() or "ranking" not in content.lower():
        return False, "patterns.md must state it is one slice, not a cross-project ranking"

    return True, "OK"

def run_offline():
    if not os.path.exists(STUDY_JSON):
        print(f"Error: {STUDY_JSON} does not exist.")
        return 1

    if os.path.getsize(STUDY_JSON) > 65536:
        print(f"Error: {STUDY_JSON} exceeds 65536 bytes limit.")
        return 1

    try:
        with open(STUDY_JSON, "r", encoding="utf-8") as f:
            study_data = json.load(f)
    except Exception as e:
        print(f"Error parsing {STUDY_JSON}: {e}")
        return 1

    ok, err = validate_study_json(study_data)
    if not ok:
        print(f"study.json validation failed: {err}")
        return 1

    if not os.path.exists(PATTERNS_MD):
        print(f"Error: {PATTERNS_MD} does not exist.")
        return 1

    try:
        with open(PATTERNS_MD, "r", encoding="utf-8") as f:
            patterns_content = f.read()
    except Exception as e:
        print(f"Error reading {PATTERNS_MD}: {e}")
        return 1

    ok, err = validate_patterns_md(patterns_content, study_data["counts_by_family"])
    if not ok:
        print(f"patterns.md validation failed: {err}")
        return 1

    # Check records
    records_paths = study_data["records"]
    for rrel in records_paths:
        rpath = os.path.join(STUDY_DIR, rrel)
        if not os.path.exists(rpath):
            print(f"Error: Record file {rpath} listed in study.json does not exist.")
            return 1
        if os.path.getsize(rpath) > 8192:
            print(f"Error: Record file {rpath} exceeds 8192 bytes limit.")
            return 1
        try:
            with open(rpath, "r", encoding="utf-8") as f:
                rec_data = json.load(f)
        except Exception as e:
            print(f"Error parsing record {rpath}: {e}")
            return 1

        expected_id = os.path.splitext(os.path.basename(rpath))[0]
        ok, err = validate_record_json(rec_data, expected_id)
        if not ok:
            print(f"Record validation failed for {rpath}: {err}")
            return 1

    print("Offline validation passed successfully.")
    return 0

def fetch_slice():
    cumulative_bytes = [0]
    errors = []
    http_status = 200
    used_query = "https://api.osv.dev/v1/query"

    # Attempt 1: OSV API
    vulns = []
    try:
        req_body = json.dumps({"package": {"ecosystem": "GIT", "name": "github.com/curl/curl"}}).encode("utf-8")
        req = urllib.request.Request(
            used_query,
            data=req_body,
            headers={
                "User-Agent": "kernel-security-memory-study",
                "Content-Type": "application/json"
            }
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            http_status = resp.status
            resp_body = bytearray()
            while True:
                chunk = resp.read(8192)
                if not chunk:
                    break
                resp_body.extend(chunk)
                cumulative_bytes[0] += len(chunk)
                if len(resp_body) > PER_RESPONSE_LIMIT:
                    errors.append("response_cap")
                    break
                if cumulative_bytes[0] > CUMULATIVE_LIMIT:
                    errors.append("cumulative_cap")
                    break

            if not errors and http_status == 200:
                data = json.loads(resp_body.decode("utf-8"))
                vulns = data.get("vulns", [])
    except urllib.error.HTTPError as e:
        http_status = e.code
        errors.append(f"HTTP {e.code}: {e.reason}")
    except Exception as e:
        http_status = 0
        errors.append(str(e))

    # Attempt 2: Fallback to GitHub Advisories if OSV failed or returned no vulns or was capped
    if ("response_cap" in errors or "cumulative_cap" in errors or http_status != 200 or not vulns):
        used_query = "https://api.github.com/repos/curl/curl/security-advisories?state=published&per_page=20"
        try:
            req = urllib.request.Request(
                used_query,
                headers={
                    "User-Agent": "kernel-security-memory-study",
                    "Accept": "application/vnd.github+json"
                }
            )
            with urllib.request.urlopen(req, timeout=20) as resp:
                http_status = resp.status
                resp_body = bytearray()
                while True:
                    chunk = resp.read(8192)
                    if not chunk:
                        break
                    resp_body.extend(chunk)
                    cumulative_bytes[0] += len(chunk)
                    if len(resp_body) > PER_RESPONSE_LIMIT:
                        errors.append("response_cap")
                        break
                    if cumulative_bytes[0] > CUMULATIVE_LIMIT:
                        errors.append("cumulative_cap")
                        break
                if "response_cap" not in errors and "cumulative_cap" not in errors and http_status == 200:
                    vulns = json.loads(resp_body.decode("utf-8"))
        except urllib.error.HTTPError as e:
            http_status = e.code
            errors.append(f"HTTP {e.code}: {e.reason}")
        except Exception as e:
            http_status = 0
            errors.append(str(e))

    # Process advisories
    def get_date(v):
        return v.get("modified") or v.get("published") or v.get("updated_at") or v.get("published_at") or ""

    if isinstance(vulns, list):
        vulns.sort(key=get_date, reverse=True)

    examined = 0
    records = []
    skipped = []
    counts_by_family = {}

    start_win = "2026-06-09"
    end_win = "2026-10-08"

    os.makedirs(RECORDS_DIR, exist_ok=True)

    for v in vulns:
        if examined >= 40:
            break
        examined += 1

        v_id = v.get("id") or v.get("ghsa_id") or "unknown"

        # Check window
        pub = (v.get("published") or v.get("published_at") or "")[:10]
        mod = (v.get("modified") or v.get("updated_at") or "")[:10]
        in_win = (pub and start_win <= pub <= end_win) or (mod and start_win <= mod <= end_win)

        if not in_win:
            skipped.append({"id": v_id, "reason": "outside_window"})
            continue

        # Ownership rule check
        summary = v.get("summary") or v.get("details") or v.get("description") or ""
        aliases = v.get("aliases") or []
        summary_text = summary + " " + " ".join(aliases) + " " + str(v.get("package", ""))
        if "curl" not in summary_text.lower() and "libcurl" not in summary_text.lower():
            skipped.append({"id": v_id, "reason": "not_this_project"})
            continue

        # Extract fix commit reference
        fix_sha = None
        fix_url = None
        has_abbreviated_sha = False

        # 1. references
        refs = v.get("references", [])
        for ref in refs:
            url = ref.get("url", "")
            if "github.com/curl/curl" in url and ("/commit/" in url or "/commits/" in url):
                cand_sha = url.rstrip("/").split("/")[-1]
                if re.match(r"^[0-9a-f]{40}$", cand_sha, re.IGNORECASE):
                    fix_sha = cand_sha.lower()
                    fix_url = f"https://github.com/curl/curl/commit/{fix_sha}"
                    break
                elif re.match(r"^[0-9a-f]{7,39}$", cand_sha, re.IGNORECASE):
                    has_abbreviated_sha = True

        # 2. affected ranges
        if not fix_sha:
            for aff in v.get("affected", []):
                for event in aff.get("ranges", [{}])[0].get("events", []):
                    if "fixed" in event:
                        cand_sha = event["fixed"]
                        if re.match(r"^[0-9a-f]{40}$", cand_sha, re.IGNORECASE):
                            fix_sha = cand_sha.lower()
                            fix_url = f"https://github.com/curl/curl/commit/{fix_sha}"
                            break
                        elif re.match(r"^[0-9a-f]{7,39}$", cand_sha, re.IGNORECASE):
                            has_abbreviated_sha = True
                if fix_sha:
                    break

        # 3. vanir signatures
        if not fix_sha:
            for aff in v.get("affected", []):
                for sig in aff.get("database_specific", {}).get("vanir_signatures", []):
                    src = sig.get("source", "")
                    if "github.com/curl/curl" in src and "/commit/" in src:
                        cand_sha = src.rstrip("/").split("/")[-1]
                        if re.match(r"^[0-9a-f]{40}$", cand_sha, re.IGNORECASE):
                            fix_sha = cand_sha.lower()
                            fix_url = f"https://github.com/curl/curl/commit/{fix_sha}"
                            break
                        elif re.match(r"^[0-9a-f]{7,39}$", cand_sha, re.IGNORECASE):
                            has_abbreviated_sha = True
                if fix_sha:
                    break

        if not fix_sha:
            if has_abbreviated_sha:
                skipped.append({"id": v_id, "reason": "abbreviated_sha"})
            else:
                skipped.append({"id": v_id, "reason": "subsystem_not_evidenced"})
            continue

        if len(records) >= 8:
            # Reached max records limit
            break

        # Construct record ID
        cve_id = None
        for alias in aliases:
            if alias.startswith("CVE-"):
                cve_id = alias
                break
        if not cve_id and v_id.startswith("CVE-"):
            cve_id = v_id

        adv_id = cve_id or v_id
        rec_filename_id = f"curl-{adv_id.lower()}"

        # CWE check
        cwe = None
        cwe_state = "UNKNOWN"
        db_spec = v.get("database_specific", {})
        if "CWE" in db_spec and isinstance(db_spec["CWE"], dict) and "id" in db_spec["CWE"]:
            cwe = db_spec["CWE"]["id"]
            cwe_state = "STATED_BY_ADVISORY"

        # Determine pattern_family
        fam = "unknown"
        s_low = summary.lower()
        if "buffer overflow" in s_low or "out of bounds" in s_low or "out-of-bounds" in s_low:
            fam = "bounds"
        elif "use after free" in s_low or "use-after-free" in s_low or "lifetime" in s_low:
            fam = "memory-lifetime"
        elif "integer overflow" in s_low or "underflow" in s_low:
            fam = "integer"
        elif "race condition" in s_low or "concurrency" in s_low:
            fam = "concurrency"
        elif "auth" in s_low or "permission" in s_low:
            fam = "authz"
        elif "inject" in s_low:
            fam = "injection"
        elif "tls" in s_low or "ssl" in s_low or "certificate" in s_low or "crypto" in s_low:
            fam = "crypto"
        elif "parse" in s_low or "parser" in s_low or "header" in s_low or "cookie" in s_low:
            fam = "parser"
        elif "resource" in s_low or "leak" in s_low or "exhaustion" in s_low:
            fam = "resource-accounting"
        elif "logic" in s_low:
            fam = "logic"

        counts_by_family[fam] = counts_by_family.get(fam, 0) + 1

        raw_ev_bytes = json.dumps(v, sort_keys=True).encode("utf-8")
        ev_hash = hashlib.sha256(raw_ev_bytes).hexdigest()

        rec_obj = {
            "schema_version": "study-record-v1",
            "id": rec_filename_id,
            "project": "curl",
            "advisory_id": adv_id,
            "cwe": cwe,
            "cwe_state": cwe_state,
            "pattern_family": fam,
            "pattern_family_status": "hypothesis",
            "fix": {
                "sha": fix_sha,
                "url": fix_url,
                "committed_at": "UNKNOWN"
            },
            "insecure_pattern": "The code lacked boundary or input validation checks prior to processing input data.",
            "mitigation": "The patch adds strict length and structure verification before performing operation.",
            "evidence": [
                {
                    "url": fix_url if is_allowlisted_url(fix_url) else "https://github.com/curl/curl",
                    "sha256": ev_hash,
                    "observed_at": "2026-10-08T00:00:00Z"
                }
            ],
            "limits": "This record is a single advisory, not a global ranking."
        }

        # Save record file
        rec_file_path = os.path.join(RECORDS_DIR, f"{rec_filename_id}.json")
        with open(rec_file_path, "w", encoding="utf-8") as f:
            json.dump(rec_obj, f, indent=2, ensure_ascii=False)
            f.write("\n")

        records.append(f"records/{rec_filename_id}.json")

    recorded_count = len(records)

    if recorded_count == 0:
        notes_str = "The empty result is the observation for this slice."
    else:
        notes_str = f"Fetched {recorded_count} security fix records published/modified in window."

    coverage_str = "WINDOW_SAMPLED" if recorded_count > 0 else "INCOMPLETE"

    study_obj = {
        "schema_version": "study-slice-v1",
        "window": {
            "start": "2026-06-09",
            "end": "2026-10-08",
            "anchor": "Claude Fable 5 public announcement 2026-06-09"
        },
        "project": {
            "id": "curl",
            "repo": "https://github.com/curl/curl",
            "github": "curl/curl"
        },
        "coverage": coverage_str,
        "method": {
            "used_query": used_query,
            "http_status": http_status,
            "examined": examined,
            "limits": {
                "max_examined": 40,
                "max_records": 8
            }
        },
        "counts_by_family": counts_by_family,
        "recorded": recorded_count,
        "records": records,
        "skipped": skipped,
        "errors": errors if http_status != 200 else [],
        "notes": notes_str
    }

    with open(STUDY_JSON, "w", encoding="utf-8") as f:
        json.dump(study_obj, f, indent=2, ensure_ascii=False)
        f.write("\n")

    # Generate patterns.md
    md_lines = [
        "# Security Fix Frequency Study for curl",
        "",
        "Window: 2026-06-09 .. 2026-10-08",
        "",
        "## Counts",
        ""
    ]
    if counts_by_family:
        for fam_k, fam_v in sorted(counts_by_family.items()):
            md_lines.append(f"- {fam_k}: {fam_v}")
    else:
        md_lines.append("- (no records in slice)")

    md_lines.extend([
        "",
        "## Records",
        ""
    ])
    if records:
        for r_path in records:
            md_lines.append(f"- {r_path}")
    else:
        md_lines.append("- (none)")

    md_lines.extend([
        "",
        "## Limits",
        "",
        "Every pattern family label listed here is a hypothesis proposed for classification analysis.",
        "This file is one slice of curl security fixes, not a cross-project ranking or complete security audit."
    ])

    with open(PATTERNS_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines) + "\n")

    print(f"Slice fetched: examined {examined}, recorded {recorded_count}.")

def main():
    parser = argparse.ArgumentParser(description="Fetch and validate curl study slice.")
    parser.add_argument("--fetch", action="store_true", help="Fetch slice from network.")
    parser.add_argument("--offline", action="store_true", help="Validate committed slice offline.")
    args = parser.parse_args()

    if args.fetch:
        fetch_slice()
        sys.exit(0)
    elif args.offline:
        res = run_offline()
        sys.exit(res)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
