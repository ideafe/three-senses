#!/usr/bin/env python3
"""
IPAWS alert-accessibility gap analysis: fetch + aggregate, Python 3.12 stdlib only.

Source dataset
    OpenFEMA "IPAWS Archived Alerts" v1
    https://www.fema.gov/api/open/v1/IpawsArchivedAlerts
    Published with a documented ~24 hour delay (see FEMA's own dataset description).

What this script does
    1. FETCH  : pages the one-year window into one JSON file per HTTP page under RAW_DIR,
                verbatim as returned (metadata block included), so every aggregate below
                can be recomputed later with --no-fetch and no network access.
    2. VERIFY : runs sanity checks (see SANITY CHECKS below) and prints "WARNING:" lines
                for any check that fails.
    3. AGGREGATE : computes the exhibit numbers and writes them to --out as JSON.

Usage
    python3 fetch_and_aggregate.py                 # fetch, verify, aggregate, write JSON
    python3 fetch_and_aggregate.py --no-fetch      # re-aggregate from RAW_DIR, no network
    python3 fetch_and_aggregate.py --raw-dir DIR --out FILE
    python3 fetch_and_aggregate.py --no-verify-xml # skip the CAP-XML cross-check refetch
    python3 fetch_and_aggregate.py --no-context    # skip the per-year dataset-context counts

Counting unit
    The dataset's unit of record is one CAP message, not one incident. An incident that is
    issued and then updated twice appears as three records (msgType Alert, Update, Update).
    "Alert" below therefore means "one archived CAP message". Every percentage is reported
    per alert message unless the field name says per_info or per_resource: a CAP <info>
    block is per-language, so a bilingual message carries the same resource list twice and
    per-resource totals would double-count it. Where per-info is the more faithful unit
    (language, WEA parameter text) both units are reported.
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import hashlib
import json
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

# ----------------------------------------------------------------------------------
# CONSTANTS: every methodological choice is a named constant so it can be audited.
# ----------------------------------------------------------------------------------

ENDPOINT = "https://www.fema.gov/api/open/v1/IpawsArchivedAlerts"
DATASETS_ENDPOINT = "https://www.fema.gov/api/open/v1/DataSets"

# Analysis window: one year, half-open [START, END). END is 00:00Z of the run date, so the
# window stops before "today"; the dataset's own ~24h publication delay means the final
# calendar day inside the window is itself partial. Both facts are measured, not assumed:
# see sanity check S7 (final-day record count) and the "window_tail" block in the output.
WINDOW_START = "2025-08-20T00:00:00.000Z"
WINDOW_END = "2026-08-20T00:00:00.000Z"

# Only status=Actual is in scope (drills/tests must not be counted as real public alerts).
# The archive turns out to contain nothing else at all; the script measures this rather
# than trusting it (sanity check S6) and reports the number excluded.
STATUS_IN_SCOPE = "Actual"

# Sub-windows: the window starts on the 20th, so calendar months would produce two partial
# rows. Twelve 20th-to-20th periods give exactly twelve full-length rows instead. Each
# sub-window is counted independently by the API ($inlinecount), which turns the by-month
# table into a sanity check on the paging (S1).
SUBWINDOW_DAY_OF_MONTH = 20

PAGE_SIZE = 1000  # OpenFEMA hard maximum for $top
SLEEP_BETWEEN_REQUESTS = 0.5  # seconds; be a polite API client
HTTP_TIMEOUT = 300
HTTP_RETRIES = 4
USER_AGENT = "chi2027-anonymous-ipaws-analysis/1.0 (research)"

# originalMessage (the raw signed CAP XML) is excluded from the bulk fetch: it is ~10-40 kB
# per record and every field used below is present in FEMA's own parsed representation.
# A deterministic sample IS refetched with originalMessage to prove the parsed fields agree
# with the source XML (sanity check S8).
SELECT_FIELDS = (
    "identifier,sent,sender,status,msgType,scope,cogId,id,code,note,incidents,info"
)
SELECT_FIELDS_XML = "identifier,sent,id,originalMessage,info"
XML_VERIFY_PER_SUBWINDOW = 20  # records per sub-window refetched with originalMessage

# Where the raw pages are cached. Portable default; override with --raw-dir or the
# IPAWS_RAW_DIR environment variable. The pages are ~86 MB for a one-year window and are
# deliberately not committed; the path actually used by a run is recorded in the output
# JSON under methodology.raw_dir.
DEFAULT_RAW_DIR = os.environ.get(
    "IPAWS_RAW_DIR", os.path.join(tempfile.gettempdir(), "ipaws-openfema-raw")
)
DEFAULT_OUT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "aggregates-2026-08-20.json"
)
MANIFEST_NAME = "_manifest.json"

# Media classification. mimeType is authoritative; the URI file extension is used only as
# an independent backstop so that a video posted under a wrong/absent mimeType cannot hide.
MIME_CLASS_RULES = (
    ("video", ("video/",)),
    ("image", ("image/",)),
    ("audio", ("audio/",)),
    ("text", ("text/",)),
)
EXT_CLASS = {
    "video": (
        "mp4",
        "mov",
        "m4v",
        "avi",
        "mkv",
        "webm",
        "3gp",
        "mpg",
        "mpeg",
        "wmv",
        "flv",
        "ts",
        "m3u8",
        "mpd",
    ),
    "image": ("jpg", "jpeg", "png", "gif", "bmp", "webp", "svg", "tif", "tiff", "heic"),
    "audio": ("mp3", "wav", "ogg", "oga", "m4a", "aac", "wma", "flac", "aiff", "au"),
    "text": ("html", "htm", "txt", "xml", "json", "pdf"),
}

# Sign-language probes. LOOSE is the literal substring grep asked for in the brief; it is
# noisy because "asl" occurs inside random hex path segments, so STRICT is reported next to
# it and every LOOSE hit is emitted verbatim for human inspection.
TEST_URI_PROBE = re.compile(r"test", re.IGNORECASE)

ASL_LOOSE = re.compile(r"asl|sign", re.IGNORECASE)
ASL_STRICT = re.compile(
    r"(?:\basl\b|[^a-z]asl[^a-z]|^asl[^a-z]|[^a-z]asl$"
    r"|sign[\s._-]*lang|signlang|american[\s._-]*sign|libras|\blsf\b|\bbsl\b)",
    re.IGNORECASE,
)

# The National Weather Service reaches IPAWS through a single sender id. Splitting on it
# separates one federal machine-to-machine originator from the ~1,200 state, local, tribal
# and other federal originators, whose practice differs on every dimension measured here.
NWS_SENDER = "w-nws.webmaster@noaa.gov"

ENGLISH_PREFIX = "en"
SPANISH_PREFIX = "es"

WEA_TEXT_PARAMS = ("CMAMtext", "CMAMlongtext")

# status=Actual does NOT mean "not a drill": the EAS/WEA required tests are transmitted as
# status Actual carrying a test SAME event code. These codes are therefore reported
# separately and excluded in the "real_events" robustness subset.
TEST_SAME_CODES = ("RWT", "RMT", "DMO", "NPT")


# ----------------------------------------------------------------------------------
# HTTP
# ----------------------------------------------------------------------------------


def http_get_json(url: str) -> dict:
    """GET with retries and a polite delay. Returns parsed JSON."""
    last_err: Exception | None = None
    for attempt in range(HTTP_RETRIES):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                body = resp.read()
            time.sleep(SLEEP_BETWEEN_REQUESTS)
            return json.loads(body)
        except (
            urllib.error.URLError,
            urllib.error.HTTPError,
            TimeoutError,
            json.JSONDecodeError,
        ) as err:
            last_err = err
            wait = SLEEP_BETWEEN_REQUESTS * (2**attempt) * 4
            print(
                f"  retry {attempt + 1}/{HTTP_RETRIES} after {type(err).__name__}: "
                f"{err} (sleeping {wait:.1f}s)",
                file=sys.stderr,
            )
            time.sleep(wait)
    raise RuntimeError(f"GET failed after {HTTP_RETRIES} attempts: {url}") from last_err


def query_url(endpoint: str, params: dict[str, str]) -> str:
    return (
        endpoint
        + "?"
        + "&".join(
            f"{k}={urllib.parse.quote(str(v), safe='')}" for k, v in params.items()
        )
    )


def api_count(odata_filter: str) -> int:
    """Server-side record count for a filter, via $inlinecount=allpages."""
    url = query_url(
        ENDPOINT,
        {
            "$inlinecount": "allpages",
            "$top": "1",
            "$select": "id",
            "$filter": odata_filter,
        },
    )
    return int(http_get_json(url)["metadata"]["count"])


# ----------------------------------------------------------------------------------
# Window / sub-window helpers
# ----------------------------------------------------------------------------------


def parse_iso_z(value: str) -> dt.datetime:
    return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
        tzinfo=dt.timezone.utc
    )


def fmt_iso_z(value: dt.datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def add_month(value: dt.datetime) -> dt.datetime:
    year, month = value.year, value.month
    return (
        value.replace(year=year + 1, month=1)
        if month == 12
        else value.replace(month=month + 1)
    )


def subwindows() -> list[tuple[str, str, str]]:
    """Twelve 20th-to-20th sub-windows: (label, start_iso, end_iso)."""
    start, end = parse_iso_z(WINDOW_START), parse_iso_z(WINDOW_END)
    out, cursor = [], start
    while cursor < end:
        nxt = min(add_month(cursor), end)
        out.append(
            (f"{cursor:%Y-%m-%d}_to_{nxt:%Y-%m-%d}", fmt_iso_z(cursor), fmt_iso_z(nxt))
        )
        cursor = nxt
    return out


def window_filter(start_iso: str, end_iso: str) -> str:
    return f"sent ge '{start_iso}' and sent lt '{end_iso}'"


# ----------------------------------------------------------------------------------
# FETCH
# ----------------------------------------------------------------------------------


def fetch_window(raw_dir: str, do_context: bool, do_verify_xml: bool) -> dict:
    """Page the whole window into raw_dir. Returns the manifest dict (also written)."""
    os.makedirs(raw_dir, exist_ok=True)
    manifest: dict = {
        "fetched_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "endpoint": ENDPOINT,
        "window": {"start": WINDOW_START, "end": WINDOW_END},
        "select_fields": SELECT_FIELDS,
        "page_size": PAGE_SIZE,
        "paging_strategy": (
            "twelve 20th-to-20th sub-windows; within each, keyset paging on `sent` "
            "ascending with an inclusive cursor (sent ge last_seen_sent) and "
            "de-duplication on the record `id`. Inclusive cursor + dedupe is used instead "
            "of $skip so that records sharing an identical `sent` timestamp can neither be "
            "skipped nor double-counted."
        ),
        "window_total_from_api": None,
        "subwindows": [],
        "pages": [],
        "dataset_context": None,
        "xml_verify_files": [],
    }

    print("Window total from API ...", flush=True)
    manifest["window_total_from_api"] = api_count(
        window_filter(WINDOW_START, WINDOW_END)
    )
    print(
        f"  {manifest['window_total_from_api']} records in "
        f"[{WINDOW_START}, {WINDOW_END})"
    )

    for label, start_iso, end_iso in subwindows():
        sub_filter = window_filter(start_iso, end_iso)
        expected = api_count(sub_filter)
        seen_ids: set[str] = set()
        cursor = start_iso
        seq, fetched_rows = 0, 0
        print(f"[{label}] expected {expected}", flush=True)
        while True:
            seq += 1
            page_filter = f"sent ge '{cursor}' and sent lt '{end_iso}'"
            url = query_url(
                ENDPOINT,
                {
                    "$top": str(PAGE_SIZE),
                    "$select": SELECT_FIELDS,
                    "$orderby": "sent asc",
                    "$filter": page_filter,
                    "$inlinecount": "allpages",
                },
            )
            payload = http_get_json(url)
            rows = payload.get("IpawsArchivedAlerts", [])
            path = os.path.join(raw_dir, f"page_{label}_{seq:03d}.json")
            blob = json.dumps(payload, sort_keys=True).encode()
            with open(path, "wb") as handle:
                handle.write(blob)
            new_ids = [r["id"] for r in rows if r["id"] not in seen_ids]
            seen_ids.update(new_ids)
            fetched_rows += len(rows)
            manifest["pages"].append(
                {
                    "file": os.path.basename(path),
                    "subwindow": label,
                    "seq": seq,
                    "rows": len(rows),
                    "new_rows": len(new_ids),
                    "remaining_from_api": int(payload["metadata"]["count"]),
                    "bytes": len(blob),
                    "sha256": hashlib.sha256(blob).hexdigest(),
                    "filter": page_filter,
                }
            )
            print(
                f"  page {seq}: {len(rows)} rows ({len(new_ids)} new), "
                f"{len(seen_ids)}/{expected}",
                flush=True,
            )
            if len(rows) < PAGE_SIZE:
                break
            last_sent = rows[-1]["sent"]
            if last_sent == cursor and len(new_ids) == 0:
                print(
                    f"  WARNING: paging stalled at {cursor} in {label}; "
                    f"more than {PAGE_SIZE} records share one timestamp."
                )
                break
            cursor = last_sent
        manifest["subwindows"].append(
            {
                "label": label,
                "start": start_iso,
                "end": end_iso,
                "expected_from_api": expected,
                "unique_ids_fetched": len(seen_ids),
                "rows_downloaded": fetched_rows,
                "pages": seq,
            }
        )

    if do_verify_xml:
        manifest["xml_verify_files"] = fetch_xml_sample(raw_dir)
    if do_context:
        manifest["dataset_context"] = fetch_dataset_context()

    with open(os.path.join(raw_dir, MANIFEST_NAME), "w") as handle:
        json.dump(manifest, handle, indent=1, sort_keys=True)
    return manifest


def fetch_xml_sample(raw_dir: str) -> list[str]:
    """Refetch the first N records of each sub-window WITH the raw CAP XML, for S8."""
    files = []
    print("Fetching CAP-XML verification sample ...", flush=True)
    for label, start_iso, end_iso in subwindows():
        url = query_url(
            ENDPOINT,
            {
                "$top": str(XML_VERIFY_PER_SUBWINDOW),
                "$select": SELECT_FIELDS_XML,
                "$orderby": "sent asc",
                "$filter": window_filter(start_iso, end_iso),
            },
        )
        payload = http_get_json(url)
        name = f"xmlverify_{label}.json"
        with open(os.path.join(raw_dir, name), "w") as handle:
            json.dump(payload, handle, sort_keys=True)
        files.append(name)
        print(f"  {label}: {len(payload.get('IpawsArchivedAlerts', []))} records")
    return files


def fetch_dataset_context() -> dict:
    """Per-year record counts + the dataset's registry entry.

    Not part of the headline numbers. It exists because the archive's composition changes
    sharply during 2023, and any citation of a one-year count has to disclose that the year
    is not comparable to earlier years.
    """

    def soft_count(odata_filter: str) -> int | None:
        """Context counts are diagnostics, never headline numbers. An unfiltered count over
        the whole 4.9M-record table can time out at the API; a failure records null here
        instead of aborting a completed page fetch."""
        try:
            return api_count(odata_filter)
        except RuntimeError as err:
            print(f"  (context count unavailable: {err})", file=sys.stderr)
            return None

    print("Fetching dataset context (per-year counts) ...", flush=True)
    years = {}
    for year in range(2012, 2027):
        years[str(year)] = soft_count(
            f"sent ge '{year}-01-01T00:00:00.000Z' and "
            f"sent lt '{year + 1}-01-01T00:00:00.000Z'"
        )
        print(f"  {year}: {years[str(year)]}")
    months_2023 = {}
    for month in range(1, 13):
        nxt_y, nxt_m = (2024, 1) if month == 12 else (2023, month + 1)
        months_2023[f"2023-{month:02d}"] = soft_count(
            f"sent ge '2023-{month:02d}-01T00:00:00.000Z' and "
            f"sent lt '{nxt_y}-{nxt_m:02d}-01T00:00:00.000Z'"
        )
    win = window_filter(WINDOW_START, WINDOW_END)
    try:
        registry = http_get_json(
            query_url(DATASETS_ENDPOINT, {"$filter": "name eq 'IpawsArchivedAlerts'"})
        )
        entry = (registry.get("DataSets") or [{}])[0]
    except RuntimeError:
        entry = {}
    return {
        "records_by_calendar_year": years,
        "records_by_month_2023": months_2023,
        "nws_sender_share": {
            "window": {
                "total": soft_count(win),
                "nws": soft_count(win + " and sender eq 'w-nws.webmaster@noaa.gov'"),
            },
            "2023_h1": {
                "total": soft_count(
                    "sent ge '2023-01-01T00:00:00.000Z' and "
                    "sent lt '2023-07-01T00:00:00.000Z'"
                ),
                "nws": soft_count(
                    "sent ge '2023-01-01T00:00:00.000Z' and "
                    "sent lt '2023-07-01T00:00:00.000Z' and "
                    "sender eq 'w-nws.webmaster@noaa.gov'"
                ),
            },
        },
        "status_filter_negative_control": {
            "note": (
                "a filter that returns everything proves nothing. These four counts "
                "show the status filter is evaluated server-side: inside the window a "
                "bogus status value returns 0 while Actual returns the full window, "
                "so 'no non-Actual records' is a property of the archive and not a "
                "silently ignored parameter. The two all-time counts are best-effort: "
                "an unfiltered scan of the 4.9M-record table can time out and is "
                "recorded as null when it does."
            ),
            "window: status eq 'Actual'": soft_count(win + " and status eq 'Actual'"),
            "window: status eq 'ActualX' (bogus value)": soft_count(
                win + " and status eq 'ActualX'"
            ),
            "window: status ne 'Actual'": soft_count(win + " and status ne 'Actual'"),
            "all time: status eq 'Actual'": soft_count("status eq 'Actual'"),
            "all time: status ne 'Actual'": soft_count("status ne 'Actual'"),
        },
        "registry": {
            k: entry.get(k)
            for k in (
                "recordCount",
                "lastRefresh",
                "lastDataSetRefresh",
                "modified",
                "temporal",
                "version",
                "deprecated",
                "depDate",
            )
        },
    }


# ----------------------------------------------------------------------------------
# LOAD
# ----------------------------------------------------------------------------------


def load_raw(raw_dir: str) -> tuple[list[dict], dict]:
    """Load every page file, de-duplicate on `id`, return (records, load_report)."""
    names = sorted(
        n for n in os.listdir(raw_dir) if n.startswith("page_") and n.endswith(".json")
    )
    if not names:
        raise SystemExit(
            f"no page_*.json files in {raw_dir}; run without --no-fetch first"
        )
    by_id: dict[str, dict] = {}
    dup_id_hits = 0
    dup_sent: list[str] = []
    rows_total = 0
    id_to_files: dict[str, list[str]] = collections.defaultdict(list)
    for name in names:
        with open(os.path.join(raw_dir, name)) as handle:
            payload = json.load(handle)
        for row in payload.get("IpawsArchivedAlerts", []):
            rows_total += 1
            rid = row["id"]
            id_to_files[rid].append(name)
            if rid in by_id:
                dup_id_hits += 1
                dup_sent.append(row["sent"])
            else:
                by_id[rid] = row
    records = sorted(by_id.values(), key=lambda r: (r["sent"], r["id"]))
    ident_counts = collections.Counter(r["identifier"] for r in records)
    repeated_identifiers = {k: v for k, v in ident_counts.items() if v > 1}
    cross_page_dupes = {
        k: sorted(set(v)) for k, v in id_to_files.items() if len(set(v)) > 1
    }
    report = {
        "page_files": len(names),
        "rows_downloaded_total": rows_total,
        "unique_records_by_id": len(records),
        "duplicate_id_rows_dropped": dup_id_hits,
        "duplicate_row_sent_values": sorted(set(dup_sent)),
        "ids_appearing_in_more_than_one_page_file": len(cross_page_dupes),
        "distinct_identifiers": len(ident_counts),
        "identifiers_used_by_more_than_one_record": len(repeated_identifiers),
        "identifiers_used_by_more_than_one_record_examples": dict(
            sorted(repeated_identifiers.items(), key=lambda kv: -kv[1])[:10]
        ),
    }
    return records, report


# ----------------------------------------------------------------------------------
# FIELD ACCESSORS (schema verified against live data 2026-08-20; see docs for the shapes)
#   info[].resource[]  -> {resourceDesc, mimeType, uri, size, derefUri}
#   info[].area[]      -> {areaDesc, polygon: {type, coordinates} | None,
#                          circle: [ {type, radius, coordinates} ] | None,
#                          geocode: [ {id, name, value} ] | None}
#   info[].parameter[] -> {name, value}      (CAP <parameter><valueName>)
#   info[].eventCode[] -> {name, value}      (CAP <eventCode><valueName>, e.g. SAME)
#   info[].category    -> [str]
# ----------------------------------------------------------------------------------


def infos(rec: dict) -> list[dict]:
    return rec.get("info") or []


def resources(rec: dict) -> list[dict]:
    return [res for info in infos(rec) for res in (info.get("resource") or [])]


def areas(rec: dict) -> list[dict]:
    return [area for info in infos(rec) for area in (info.get("area") or [])]


def parameters(rec: dict) -> list[dict]:
    return [p for info in infos(rec) for p in (info.get("parameter") or [])]


def event_codes(rec: dict, name: str) -> list[str]:
    return [
        ec.get("value")
        for info in infos(rec)
        for ec in (info.get("eventCode") or [])
        if ec.get("name") == name
    ]


def languages(rec: dict) -> list[str]:
    return [(info.get("language") or "").strip() for info in infos(rec)]


def uri_ext(uri: str | None) -> str:
    if not uri:
        return ""
    path = urllib.parse.urlparse(uri).path
    return path.rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1] else ""


def mime_class(mime: str | None) -> str:
    value = (mime or "").strip().lower()
    if not value:
        return "missing"
    for label, prefixes in MIME_CLASS_RULES:
        if value.startswith(prefixes):
            return label
    for label in ("video", "image", "audio"):
        if label in value:
            return label
    return "other"


def ext_class(uri: str | None) -> str:
    ext = uri_ext(uri)
    if not ext:
        return "none"
    for label, exts in EXT_CLASS.items():
        if ext in exts:
            return label
    return "other"


def geometry_bucket(rec: dict) -> str:
    has_poly = any(a.get("polygon") for a in areas(rec))
    has_circle = any(a.get("circle") for a in areas(rec))
    has_geocode = any(a.get("geocode") for a in areas(rec))
    if has_poly:
        return "polygon"
    if has_circle:
        return "circle_only"
    if has_geocode:
        return "geocode_only"
    if areas(rec):
        return "area_description_only"
    return "no_area_element"


def polygon_ring_count(area: dict) -> int:
    """Number of CAP <polygon> elements represented in one parsed area.

    Verified against the source XML (check S8): FEMA renders N CAP <polygon> elements of
    one <area> as a GeoJSON MultiPolygon whose coordinates list holds a single member
    containing N rings. Nothing is dropped, but the nesting is one level deeper than a
    naive reading suggests, so rings must be summed one level in. (Side effect worth
    knowing for any consumer: a strict GeoJSON reader treats rings 2..N of a member as
    holes in ring 1 rather than as separate areas.)
    """
    poly = area.get("polygon")
    if not poly:
        return 0
    if isinstance(poly, dict):
        coords = poly.get("coordinates") or []
        if poly.get("type") == "MultiPolygon":
            return sum(len(member) for member in coords) or len(coords)
        return len(coords) or 1
    if isinstance(poly, list):
        return len(poly)
    return 1


# ----------------------------------------------------------------------------------
# AGGREGATE
# ----------------------------------------------------------------------------------


def stringify_keys(node):
    """JSON object keys must be strings; several counters are keyed on fields that can be
    null in the source data (sender, event, severity). Null becomes "(absent)" so the
    output stays sortable and diffable."""
    if isinstance(node, dict):
        return {
            ("(absent)" if k is None else str(k)): stringify_keys(v)
            for k, v in node.items()
        }
    if isinstance(node, list):
        return [stringify_keys(v) for v in node]
    return node


def pct(numerator: int, denominator: int) -> float:
    return round(100.0 * numerator / denominator, 2) if denominator else 0.0


def aggregate(records: list[dict]) -> dict:
    total = len(records)
    out: dict = {"total_alert_messages": total}

    # -- 1. msgType ---------------------------------------------------------------
    out["msgType"] = dict(
        collections.Counter(r.get("msgType") for r in records).most_common()
    )
    out["scope"] = dict(
        collections.Counter(r.get("scope") for r in records).most_common()
    )
    out["status"] = dict(
        collections.Counter(r.get("status") for r in records).most_common()
    )

    # -- 2. multimedia resources --------------------------------------------------
    res_rows: list[tuple[dict, dict]] = [
        (rec, res) for rec in records for res in resources(rec)
    ]
    mime_counter = collections.Counter(
        (r.get("mimeType") or "(absent)") for _, r in res_rows
    )
    class_counter = collections.Counter(
        mime_class(r.get("mimeType")) for _, r in res_rows
    )
    ext_counter = collections.Counter(ext_class(r.get("uri")) for _, r in res_rows)
    cross = collections.Counter(
        (mime_class(r.get("mimeType")), ext_class(r.get("uri"))) for _, r in res_rows
    )
    # distinct URIs per alert: a bilingual message repeats its resource list per <info>
    distinct_uri_rows = 0
    alerts_with_resource = 0
    alerts_by_class: dict[str, int] = collections.Counter()
    for rec in records:
        rs = resources(rec)
        if rs:
            alerts_with_resource += 1
        seen = set()
        for r in rs:
            key = (r.get("uri"), r.get("mimeType"), r.get("resourceDesc"))
            if key in seen:
                continue
            seen.add(key)
            distinct_uri_rows += 1
        for cls in {mime_class(r.get("mimeType")) for r in rs}:
            alerts_by_class[cls] += 1

    disagreements = [
        {
            "sent": rec["sent"],
            "identifier": rec["identifier"],
            "mimeType": r.get("mimeType"),
            "uri": r.get("uri"),
            "resourceDesc": r.get("resourceDesc"),
            "mime_class": mime_class(r.get("mimeType")),
            "ext_class": ext_class(r.get("uri")),
        }
        for rec, r in res_rows
        if ext_class(r.get("uri")) in ("video", "image")
        and mime_class(r.get("mimeType")) != ext_class(r.get("uri"))
    ]

    def asl_hits(pattern: re.Pattern) -> list[dict]:
        hits = []
        for rec, r in res_rows:
            hay = f"{r.get('resourceDesc') or ''} {r.get('uri') or ''}"
            if pattern.search(hay):
                hits.append(
                    {
                        "sent": rec["sent"],
                        "identifier": rec["identifier"],
                        "sender": rec.get("sender"),
                        "resourceDesc": r.get("resourceDesc"),
                        "mimeType": r.get("mimeType"),
                        "uri": r.get("uri"),
                    }
                )
        return hits

    loose = asl_hits(ASL_LOOSE)
    strict = asl_hits(ASL_STRICT)
    out["multimedia"] = {
        "alerts_with_at_least_one_resource": alerts_with_resource,
        "alerts_with_at_least_one_resource_pct": pct(alerts_with_resource, total),
        "alerts_with_no_resource": total - alerts_with_resource,
        "resource_entries_per_info_total": len(res_rows),
        "resource_entries_distinct_per_alert_total": distinct_uri_rows,
        "mimeType_frequency_per_info": dict(mime_counter.most_common()),
        "media_class_per_info": dict(class_counter.most_common()),
        "media_class_by_uri_extension_per_info": dict(ext_counter.most_common()),
        "mime_class_vs_ext_class_per_info": {
            f"{a}|{b}": n for (a, b), n in cross.most_common()
        },
        "alerts_with_at_least_one_resource_by_class": dict(
            collections.Counter(alerts_by_class).most_common()
        ),
        "video_resources": class_counter.get("video", 0),
        "image_resources": class_counter.get("image", 0),
        "audio_resources": class_counter.get("audio", 0),
        "video_or_image_resources": class_counter.get("video", 0)
        + class_counter.get("image", 0),
        "video_or_image_share_of_resources_pct": pct(
            class_counter.get("video", 0) + class_counter.get("image", 0), len(res_rows)
        ),
        "audio_share_of_resources_pct": pct(
            class_counter.get("audio", 0), len(res_rows)
        ),
        "resources_with_derefUri": sum(1 for _, r in res_rows if r.get("derefUri")),
        "resourceDesc_frequency_per_info": dict(
            collections.Counter(
                (r.get("resourceDesc") or "(absent)") for _, r in res_rows
            ).most_common(25)
        ),
        "extension_video_or_image_but_other_mimetype": disagreements,
        "resource_uris_containing_test": sum(
            1 for _, r in res_rows if TEST_URI_PROBE.search(r.get("uri") or "")
        ),
        "resource_uri_filenames_containing_test_sample": sorted(
            {
                (r.get("uri") or "").rsplit("/", 1)[-1]
                for _, r in res_rows
                if TEST_URI_PROBE.search(r.get("uri") or "")
            }
        )[:20],
        "sign_language_probe": {
            "loose_regex": ASL_LOOSE.pattern,
            "loose_matches": len(loose),
            "loose_matches_verbatim": loose[:50],
            "strict_regex": ASL_STRICT.pattern,
            "strict_matches": len(strict),
            "strict_matches_verbatim": strict[:50],
        },
    }

    # -- 3. language --------------------------------------------------------------
    lang_per_info = collections.Counter(
        lang or "(absent)" for rec in records for lang in languages(rec)
    )
    alerts_non_english = 0
    alerts_es = 0
    alerts_all_non_english = 0
    third_lang_alerts: dict[str, int] = collections.Counter()
    for rec in records:
        langs = [lg.lower() for lg in languages(rec)]
        if not langs:
            continue
        non_en = [lg for lg in langs if not lg.startswith(ENGLISH_PREFIX)]
        if non_en:
            alerts_non_english += 1
        if any(lg.startswith(SPANISH_PREFIX) for lg in langs):
            alerts_es += 1
        if all(not lg.startswith(ENGLISH_PREFIX) for lg in langs):
            alerts_all_non_english += 1
        for lg in {lg for lg in non_en if not lg.startswith(SPANISH_PREFIX)}:
            third_lang_alerts[lg] += 1
    out["language"] = {
        "language_frequency_per_info": dict(lang_per_info.most_common()),
        "distinct_language_tags": sorted(lang_per_info),
        "alerts_with_any_non_english_info": alerts_non_english,
        "alerts_with_any_non_english_info_pct": pct(alerts_non_english, total),
        "alerts_with_spanish_info": alerts_es,
        "alerts_with_spanish_info_pct": pct(alerts_es, total),
        "alerts_with_no_english_info": alerts_all_non_english,
        "alerts_with_third_language_info": dict(third_lang_alerts.most_common()),
        "info_blocks_total": sum(len(infos(r)) for r in records),
        "info_blocks_per_alert_frequency": dict(
            collections.Counter(len(infos(r)) for r in records).most_common()
        ),
    }

    # -- 4. geometry --------------------------------------------------------------
    geo = collections.Counter(geometry_bucket(rec) for rec in records)
    out["geometry"] = {
        "buckets_per_alert": dict(geo.most_common()),
        "buckets_per_alert_pct": {k: pct(v, total) for k, v in geo.most_common()},
        "definition": (
            "mutually exclusive, in priority order: polygon (>=1 area with a "
            "polygon), circle_only, geocode_only, area_description_only "
            "(areaDesc but no polygon/circle/geocode), no_area_element"
        ),
        "areas_with_a_polygon": sum(
            1 for rec in records for a in areas(rec) if a.get("polygon")
        ),
        "cap_polygon_elements_total": sum(
            polygon_ring_count(a) for rec in records for a in areas(rec)
        ),
        "circle_elements_total": sum(
            len(a.get("circle") or []) for rec in records for a in areas(rec)
        ),
        "areas_per_alert_frequency": dict(
            collections.Counter(len(areas(r)) for r in records).most_common(12)
        ),
        "geocode_name_frequency": dict(
            collections.Counter(
                g.get("name")
                for rec in records
                for a in areas(rec)
                for g in (a.get("geocode") or [])
            ).most_common(12)
        ),
    }

    # -- 5. WEA text --------------------------------------------------------------
    param_names = collections.Counter(
        p.get("name") for rec in records for p in parameters(rec)
    )
    wea: dict = {"parameter_name_frequency_per_info": dict(param_names.most_common(30))}
    for name in WEA_TEXT_PARAMS:
        have = sum(
            1 for rec in records if any(p.get("name") == name for p in parameters(rec))
        )
        wea[f"alerts_with_{name}"] = have
        wea[f"alerts_with_{name}_pct"] = pct(have, total)
    both = sum(
        1
        for rec in records
        if all(
            any(p.get("name") == n for p in parameters(rec)) for n in WEA_TEXT_PARAMS
        )
    )
    either = sum(
        1
        for rec in records
        if any(p.get("name") in WEA_TEXT_PARAMS for p in parameters(rec))
    )
    wea["alerts_with_both_CMAM_params"] = both
    wea["alerts_with_either_CMAM_param"] = either
    wea["alerts_with_either_CMAM_param_pct"] = pct(either, total)
    wea["alerts_with_WEAHandling"] = sum(
        1
        for rec in records
        if any(p.get("name") == "WEAHandling" for p in parameters(rec))
    )
    # per-info view: a bilingual WEA carries one CMAMtext per language
    wea["CMAMtext_entries_per_info"] = sum(
        1 for rec in records for p in parameters(rec) if p.get("name") == "CMAMtext"
    )
    wea["CMAMlongtext_entries_per_info"] = sum(
        1 for rec in records for p in parameters(rec) if p.get("name") == "CMAMlongtext"
    )
    # of the WEA subset, how many are bilingual / carry multimedia
    wea_recs = [
        rec
        for rec in records
        if any(p.get("name") in WEA_TEXT_PARAMS for p in parameters(rec))
    ]
    wea["wea_subset_alerts"] = len(wea_recs)
    wea["wea_subset_with_spanish_info"] = sum(
        1
        for rec in wea_recs
        if any((lg or "").lower().startswith(SPANISH_PREFIX) for lg in languages(rec))
    )
    wea["wea_subset_with_spanish_info_pct"] = pct(
        wea["wea_subset_with_spanish_info"], len(wea_recs)
    )
    wea["wea_subset_with_any_resource"] = sum(1 for rec in wea_recs if resources(rec))
    out["wea_text"] = wea

    # -- 6. by sub-window ---------------------------------------------------------
    buckets: dict[str, list[dict]] = {label: [] for label, _, _ in subwindows()}
    bounds = [(label, start, end) for label, start, end in subwindows()]
    for rec in records:
        for label, start, end in bounds:
            if start <= rec["sent"] < end:
                buckets[label].append(rec)
                break
    rows = []
    for label, start, end in bounds:
        group = buckets[label]
        n = len(group)
        es = sum(
            1
            for r in group
            if any((lg or "").lower().startswith(SPANISH_PREFIX) for lg in languages(r))
        )
        vid_img = sum(
            1
            for r in group
            if any(
                mime_class(x.get("mimeType")) in ("video", "image")
                for x in resources(r)
            )
        )
        geocode_only = sum(1 for r in group if geometry_bucket(r) == "geocode_only")
        any_res = sum(1 for r in group if resources(r))
        nws = sum(1 for r in group if r.get("sender") == NWS_SENDER)
        es_non_nws = sum(
            1
            for r in group
            if r.get("sender") != NWS_SENDER
            and any(
                (lg or "").lower().startswith(SPANISH_PREFIX) for lg in languages(r)
            )
        )
        rows.append(
            {
                "period": label,
                "start": start,
                "end": end,
                "total": n,
                "nws_sender": nws,
                "nws_sender_pct": pct(nws, n),
                "spanish": es,
                "spanish_pct": pct(es, n),
                "spanish_non_nws": es_non_nws,
                "spanish_non_nws_pct": pct(es_non_nws, n - nws),
                "video_or_image": vid_img,
                "video_or_image_pct": pct(vid_img, n),
                "geocode_only": geocode_only,
                "geocode_only_pct": pct(geocode_only, n),
                "any_resource": any_res,
                "any_resource_pct": pct(any_res, n),
            }
        )
    out["by_period"] = rows

    # -- 7. SAME event codes ------------------------------------------------------
    same_per_alert = collections.Counter()
    for rec in records:
        for code in set(event_codes(rec, "SAME")):
            same_per_alert[code] += 1
    out["same_event_codes"] = {
        "counted_as": "distinct SAME eventCode values per alert message",
        "alerts_with_a_SAME_code": sum(
            1 for rec in records if event_codes(rec, "SAME")
        ),
        "top_10": dict(same_per_alert.most_common(10)),
        "distinct_codes": len(same_per_alert),
        "full_table": dict(same_per_alert.most_common()),
    }

    # -- context: originators / events -------------------------------------------
    out["originators"] = {
        "distinct_senders": len({r.get("sender") for r in records}),
        "top_20_senders": dict(
            collections.Counter(r.get("sender") for r in records).most_common(20)
        ),
        "nws_sender_alerts": sum(1 for r in records if r.get("sender") == NWS_SENDER),
    }
    test_flagged = [
        r for r in records if any(c in TEST_SAME_CODES for c in event_codes(r, "SAME"))
    ]
    out["test_traffic"] = {
        "definition": (
            "alert messages carrying a SAME eventCode in "
            f"{list(TEST_SAME_CODES)}. These are required EAS/WEA tests and "
            "demos; the archive transmits them with status=Actual, so a "
            "status filter alone does not remove them."
        ),
        "alerts_with_a_test_same_code": len(test_flagged),
        "alerts_with_a_test_same_code_pct": pct(len(test_flagged), total),
        "by_code": dict(
            collections.Counter(
                c
                for r in records
                for c in set(event_codes(r, "SAME"))
                if c in TEST_SAME_CODES
            ).most_common()
        ),
        "test_alerts_with_any_resource": sum(1 for r in test_flagged if resources(r)),
        "resource_entries_on_test_alerts": sum(len(resources(r)) for r in test_flagged),
    }
    out["events"] = {
        "top_20_event_strings_per_alert": dict(
            collections.Counter(
                (infos(r)[0].get("event") if infos(r) else None) for r in records
            ).most_common(20)
        ),
        "severity_first_info": dict(
            collections.Counter(
                (infos(r)[0].get("severity") if infos(r) else None) for r in records
            ).most_common()
        ),
        "urgency_first_info": dict(
            collections.Counter(
                (infos(r)[0].get("urgency") if infos(r) else None) for r in records
            ).most_common()
        ),
    }
    return out


def aggregate_subset(records: list[dict], predicate) -> dict:
    """Headline numbers recomputed on a subset (used for the msgType=Alert robustness cut)."""
    subset = [r for r in records if predicate(r)]
    n = len(subset)
    res_rows = [res for rec in subset for res in resources(rec)]
    cc = collections.Counter(mime_class(r.get("mimeType")) for r in res_rows)
    return {
        "alert_messages": n,
        "alerts_with_any_resource": sum(1 for r in subset if resources(r)),
        "alerts_with_any_resource_pct": pct(sum(1 for r in subset if resources(r)), n),
        "resource_entries_per_info": len(res_rows),
        "audio_resources": cc.get("audio", 0),
        "video_resources": cc.get("video", 0),
        "image_resources": cc.get("image", 0),
        "alerts_with_spanish_info": sum(
            1
            for r in subset
            if any((lg or "").lower().startswith(SPANISH_PREFIX) for lg in languages(r))
        ),
        "alerts_with_spanish_info_pct": pct(
            sum(
                1
                for r in subset
                if any(
                    (lg or "").lower().startswith(SPANISH_PREFIX) for lg in languages(r)
                )
            ),
            n,
        ),
        "geometry_buckets": dict(
            collections.Counter(geometry_bucket(r) for r in subset).most_common()
        ),
        "geocode_only_pct": pct(
            sum(1 for r in subset if geometry_bucket(r) == "geocode_only"), n
        ),
        "alerts_with_CMAMtext": sum(
            1 for r in subset if any(p.get("name") == "CMAMtext" for p in parameters(r))
        ),
        "alerts_with_CMAMtext_pct": pct(
            sum(
                1
                for r in subset
                if any(p.get("name") == "CMAMtext" for p in parameters(r))
            ),
            n,
        ),
    }


# ----------------------------------------------------------------------------------
# SANITY CHECKS
# ----------------------------------------------------------------------------------


def sanity_checks(
    records: list[dict], load_report: dict, manifest: dict | None, raw_dir: str
) -> dict:
    checks: list[dict] = []

    def add(cid: str, name: str, ok: bool | None, detail: dict) -> None:
        checks.append({"id": cid, "check": name, "passed": ok, "detail": detail})

    total = len(records)

    # S1 sub-window counts sum to the whole-window count, and each matches what was paged
    if manifest:
        sub = manifest.get("subwindows") or []
        sum_expected = sum(s["expected_from_api"] for s in sub)
        window_total = manifest.get("window_total_from_api")
        add(
            "S1a",
            "sum(sub-window $inlinecount) == whole-window $inlinecount",
            sum_expected == window_total,
            {
                "sum_of_subwindows": sum_expected,
                "whole_window": window_total,
                "difference": (sum_expected - (window_total or 0)),
            },
        )
        mism = [
            {
                "subwindow": s["label"],
                "expected": s["expected_from_api"],
                "unique_fetched": s["unique_ids_fetched"],
            }
            for s in sub
            if s["expected_from_api"] != s["unique_ids_fetched"]
        ]
        add(
            "S1b",
            "per sub-window: unique records paged == $inlinecount",
            not mism,
            {"mismatched_subwindows": mism, "subwindows_checked": len(sub)},
        )
        add(
            "S1c",
            "pages x page_size covers the reported total",
            None,
            {
                "pages": len(manifest.get("pages") or []),
                "page_size": manifest["page_size"],
                "max_capacity": len(manifest.get("pages") or [])
                * manifest["page_size"],
                "records_loaded": total,
                "note": "informational: keyset paging emits a short final page per sub-window,"
                " so capacity strictly exceeds the record count",
            },
        )
        add(
            "S2",
            "records loaded == whole-window $inlinecount at fetch time",
            total == window_total,
            {
                "records_loaded": total,
                "api_window_total": window_total,
                "difference": total - (window_total or 0),
            },
        )
    else:
        add(
            "S1",
            "sub-window/window count reconciliation",
            None,
            {"note": f"no {MANIFEST_NAME} in {raw_dir}; run a fetch to produce it"},
        )

    # S3 duplicate detection across pages: every duplicate must be explained by the
    # inclusive keyset cursor, i.e. its `sent` must equal a continuation page's cursor.
    # A duplicate anywhere else would mean the paging itself is unsound.
    cursors: set[str] = set()
    continuation_pages = 0
    if manifest:
        for page in manifest.get("pages") or []:
            if page["seq"] > 1:
                continuation_pages += 1
                match = re.search(r"sent ge '([^']+)'", page["filter"])
                if match:
                    cursors.add(match.group(1))
    unexplained = (
        [v for v in load_report["duplicate_row_sent_values"] if v not in cursors]
        if manifest
        else []
    )
    add(
        "S3",
        "every duplicate row sits exactly on a continuation-page cursor",
        (not unexplained) if manifest else None,
        {
            "rows_downloaded_total": load_report["rows_downloaded_total"],
            "unique_records_by_id": load_report["unique_records_by_id"],
            "duplicate_id_rows_dropped": load_report["duplicate_id_rows_dropped"],
            "continuation_pages": continuation_pages,
            "duplicate_sent_values_not_at_a_cursor": unexplained,
            "ids_in_more_than_one_page_file": load_report[
                "ids_appearing_in_more_than_one_page_file"
            ],
            "note": "the cursor is inclusive (sent ge last_seen) so each continuation page "
            "re-delivers the boundary record(s) on purpose; dropping them by `id` is "
            "what makes tied timestamps safe.",
        },
    )

    # S4 identifier uniqueness (informational: CAP identifiers should be unique per message)
    add(
        "S4",
        "each CAP identifier maps to exactly one record",
        load_report["identifiers_used_by_more_than_one_record"] == 0,
        {
            "distinct_identifiers": load_report["distinct_identifiers"],
            "records": total,
            "identifiers_reused": load_report[
                "identifiers_used_by_more_than_one_record"
            ],
            "examples": load_report[
                "identifiers_used_by_more_than_one_record_examples"
            ],
        },
    )

    # S5 every record inside the window
    out_of_window = [
        r["sent"] for r in records if not (WINDOW_START <= r["sent"] < WINDOW_END)
    ]
    add(
        "S5",
        "every loaded record has sent inside [WINDOW_START, WINDOW_END)",
        not out_of_window,
        {
            "out_of_window": len(out_of_window),
            "examples": out_of_window[:5],
            "min_sent": records[0]["sent"] if records else None,
            "max_sent": records[-1]["sent"] if records else None,
        },
    )

    # S6 status scope
    status_counts = collections.Counter(r.get("status") for r in records)
    non_actual = total - status_counts.get(STATUS_IN_SCOPE, 0)
    add(
        "S6",
        f"records outside status={STATUS_IN_SCOPE} are excluded and counted",
        True,
        {
            "status_counts": dict(status_counts),
            "excluded_non_actual": non_actual,
            "note": "the archive contains no non-Actual records in this window; the "
            "negative control in dataset_context shows the status filter is "
            "nonetheless applied server-side",
        },
    )

    # S7 final-day completeness
    last_day = WINDOW_END[:8] + f"{int(WINDOW_END[8:10]) - 1:02d}"
    tail = [r for r in records if r["sent"].startswith(last_day)]
    prior_days = collections.Counter(r["sent"][:10] for r in records)
    day_values = [v for k, v in prior_days.items() if k != last_day]
    median = sorted(day_values)[len(day_values) // 2] if day_values else 0
    add(
        "S7",
        "final calendar day in the window is flagged as partial",
        None,
        {
            "final_day": last_day,
            "records_on_final_day": len(tail),
            "median_records_per_other_day": median,
            "share_of_window_pct": pct(len(tail), total),
            "note": "FEMA publishes with a ~24h delay, so the last day inside the window is "
            "incomplete. It is retained (the window bound is a fixed constant) and "
            "reported here so a reviewer can see the effect is negligible.",
        },
    )

    # S8 CAP-XML cross-check
    xml_files = sorted(
        n
        for n in os.listdir(raw_dir)
        if n.startswith("xmlverify_") and n.endswith(".json")
    )
    if xml_files:
        checked = 0
        mismatches: list[dict] = []
        tallies = collections.Counter()
        for name in xml_files:
            with open(os.path.join(raw_dir, name)) as handle:
                payload = json.load(handle)
            for row in payload.get("IpawsArchivedAlerts", []):
                xml = row.get("originalMessage") or ""
                if not xml:
                    continue
                checked += 1
                parsed = {
                    "resource": len(resources(row)),
                    "polygon": sum(polygon_ring_count(a) for a in areas(row)),
                    "circle": sum(len(a.get("circle") or []) for a in areas(row)),
                    "CMAMtext": sum(
                        1 for p in parameters(row) if p.get("name") == "CMAMtext"
                    ),
                    "language_es": sum(
                        1
                        for lg in languages(row)
                        if lg.lower().startswith(SPANISH_PREFIX)
                    ),
                }
                from_xml = {
                    "resource": len(re.findall(r"<resource>", xml)),
                    "polygon": len(re.findall(r"<polygon>", xml)),
                    "circle": len(re.findall(r"<circle>", xml)),
                    "CMAMtext": len(
                        re.findall(r"<valueName>\s*CMAMtext\s*</valueName>", xml)
                    ),
                    "language_es": len(re.findall(r"<language>\s*es", xml)),
                }
                parsed["polygon_present"] = 1 if parsed["polygon"] else 0
                from_xml["polygon_present"] = 1 if from_xml["polygon"] else 0
                for key in parsed:
                    if parsed[key] == from_xml[key]:
                        tallies[f"{key}:agree"] += 1
                    else:
                        tallies[f"{key}:differ"] += 1
                        mismatches.append(
                            {
                                "identifier": row.get("identifier"),
                                "field": key,
                                "parsed": parsed[key],
                                "xml": from_xml[key],
                            }
                        )
        add(
            "S8",
            "FEMA's parsed fields agree with the original CAP XML on a sample",
            not mismatches,
            {
                "records_checked": checked,
                "files": len(xml_files),
                "fields_compared": [
                    "resource",
                    "polygon (CAP element count)",
                    "polygon_present",
                    "circle",
                    "CMAMtext",
                    "language starting with es",
                ],
                "agreement": dict(tallies),
                "mismatches": mismatches[:20],
                "note": "counts are taken from the raw signed CAP XML in originalMessage with "
                "element-level regexes and compared to the parsed fields this script "
                "actually reads. A disagreement here would invalidate the aggregates.",
            },
        )
    else:
        add(
            "S8",
            "CAP-XML cross-check",
            None,
            {"note": "no xmlverify_*.json in raw dir (fetched with --no-verify-xml?)"},
        )

    # S9 info block presence
    no_info = [r for r in records if not infos(r)]
    add(
        "S9",
        "records carrying no <info> block are counted, not dropped",
        None,
        {
            "records_without_info": len(no_info),
            "share_pct": pct(len(no_info), total),
            "msgType_of_those": dict(
                collections.Counter(r.get("msgType") for r in no_info).most_common()
            ),
            "note": "CAP permits an info-less Cancel. Such records land in the "
            "no_area_element geometry bucket and in no language bucket; they are "
            "kept in the denominator because they are real archived messages.",
        },
    )

    failed = [c["id"] for c in checks if c["passed"] is False]
    return {"checks": checks, "failed": failed, "all_passed": not failed}


# ----------------------------------------------------------------------------------
# REPORT
# ----------------------------------------------------------------------------------


def print_report(
    agg: dict, checks: dict, load_report: dict, manifest: dict | None
) -> None:
    def line(text: str = "") -> None:
        print(text)

    total = agg["total_alert_messages"]
    line("=" * 78)
    line("IPAWS ARCHIVED ALERTS: ALERT-ACCESSIBILITY AGGREGATES")
    line(f"window [{WINDOW_START}, {WINDOW_END})   status={STATUS_IN_SCOPE}")
    line("=" * 78)
    line(f"Total alert messages                 : {total}")
    line(f"msgType split                        : {agg['msgType']}")
    line(
        f"Excluded as non-{STATUS_IN_SCOPE}                : "
        f"{total - agg['status'].get(STATUS_IN_SCOPE, 0)}"
    )
    line()
    mm = agg["multimedia"]
    line("-- MULTIMEDIA ---------------------------------------------------------")
    line(
        f"Alerts with >=1 resource             : {mm['alerts_with_at_least_one_resource']}"
        f" ({mm['alerts_with_at_least_one_resource_pct']}%)"
    )
    line(
        f"Resource entries (per info block)    : {mm['resource_entries_per_info_total']}"
    )
    line(
        f"Resource entries (distinct per alert): "
        f"{mm['resource_entries_distinct_per_alert_total']}"
    )
    line(
        f"  audio                              : {mm['audio_resources']} "
        f"({mm['audio_share_of_resources_pct']}% of resources)"
    )
    line(f"  video                              : {mm['video_resources']}")
    line(f"  image                              : {mm['image_resources']}")
    line(
        f"  video+image                        : {mm['video_or_image_resources']} "
        f"({mm['video_or_image_share_of_resources_pct']}% of resources)"
    )
    line("mimeType frequency table:")
    for key, value in mm["mimeType_frequency_per_info"].items():
        line(f"    {value:>7}  {key}")
    line(
        f"Resource URIs containing 'test'    : "
        f"{mm['resource_uris_containing_test']} of "
        f"{mm['resource_entries_per_info_total']}"
    )
    line(
        f"Sign-language probe: loose={mm['sign_language_probe']['loose_matches']} "
        f"strict={mm['sign_language_probe']['strict_matches']}"
    )
    for hit in mm["sign_language_probe"]["loose_matches_verbatim"][:10]:
        line(
            f"    LOOSE HIT {hit['sent']} desc={hit['resourceDesc']!r} "
            f"uri={hit['uri']!r}"
        )
    line()
    lang = agg["language"]
    line("-- LANGUAGE -----------------------------------------------------------")
    line(
        f"Alerts with any non-English info     : "
        f"{lang['alerts_with_any_non_english_info']} "
        f"({lang['alerts_with_any_non_english_info_pct']}%)"
    )
    line(
        f"Alerts with a Spanish info block     : {lang['alerts_with_spanish_info']} "
        f"({lang['alerts_with_spanish_info_pct']}%)"
    )
    line(
        f"Alerts with no English info at all   : {lang['alerts_with_no_english_info']}"
    )
    line(
        f"Third languages (per alert)          : "
        f"{lang['alerts_with_third_language_info'] or '{}'}"
    )
    line(f"Language tags present                : {lang['distinct_language_tags']}")
    line()
    geo = agg["geometry"]
    line("-- GEOMETRY (mutually exclusive, per alert) ---------------------------")
    for key, value in geo["buckets_per_alert"].items():
        line(f"    {value:>7}  {pct(value, total):>6}%  {key}")
    line()
    wea = agg["wea_text"]
    line("-- WEA TEXT PARAMETERS ------------------------------------------------")
    for name in WEA_TEXT_PARAMS:
        line(
            f"Alerts with {name:<13}            : {wea['alerts_with_' + name]} "
            f"({wea['alerts_with_' + name + '_pct']}%)"
        )
    line(
        f"Alerts with either                   : "
        f"{wea['alerts_with_either_CMAM_param']} "
        f"({wea['alerts_with_either_CMAM_param_pct']}%)"
    )
    line(
        f"Alerts with both                     : {wea['alerts_with_both_CMAM_params']}"
    )
    line(
        f"WEA subset with Spanish info         : "
        f"{wea['wea_subset_with_spanish_info']} "
        f"({wea['wea_subset_with_spanish_info_pct']}%)"
    )
    line(
        f"WEA subset with any resource         : {wea['wea_subset_with_any_resource']}"
    )
    line()
    line("-- BY PERIOD ----------------------------------------------------------")
    line(
        f"{'period':<26}{'total':>7}{'%es':>8}{'%vid/img':>10}"
        f"{'%geocode-only':>15}{'%NWS':>8}{'%es non-NWS':>13}"
    )
    for row in agg["by_period"]:
        line(
            f"{row['period']:<26}{row['total']:>7}{row['spanish_pct']:>8}"
            f"{row['video_or_image_pct']:>10}{row['geocode_only_pct']:>15}"
            f"{row['nws_sender_pct']:>8}{row['spanish_non_nws_pct']:>13}"
        )
    line()
    line("-- TOP 10 SAME EVENT CODES -------------------------------------------")
    for key, value in agg["same_event_codes"]["top_10"].items():
        line(f"    {value:>7}  {key}")
    line(
        f"Alerts carrying any SAME code        : "
        f"{agg['same_event_codes']['alerts_with_a_SAME_code']} "
        f"({pct(agg['same_event_codes']['alerts_with_a_SAME_code'], total)}%)"
    )
    line()
    tt = agg["test_traffic"]
    line("-- TEST TRAFFIC INSIDE status=Actual ---------------------------------")
    line(
        f"Alerts with a test SAME code         : "
        f"{tt['alerts_with_a_test_same_code']} "
        f"({tt['alerts_with_a_test_same_code_pct']}%)  {tt['by_code']}"
    )
    line(
        f"  of which carry a resource          : {tt['test_alerts_with_any_resource']} "
        f"({tt['resource_entries_on_test_alerts']} resource entries)"
    )
    line()
    line("-- ROBUSTNESS: msgType=Alert only ------------------------------------")
    for key, value in agg["subset_msgtype_alert"].items():
        line(f"    {key}: {value}")
    line()
    line("-- ROBUSTNESS: msgType=Alert, test SAME codes removed ----------------")
    for key, value in agg["subset_real_events"].items():
        line(f"    {key}: {value}")
    line()
    line("-- BY ORIGINATOR CLASS -----------------------------------------------")
    for cls in ("nws", "non_nws"):
        blk = agg["by_originator_class"][cls]
        line(
            f"  {cls}: n={blk['alert_messages']} "
            f"es={blk['alerts_with_spanish_info']} "
            f"({blk['alerts_with_spanish_info_pct']}%) "
            f"any_resource={blk['alerts_with_any_resource']} "
            f"({blk['alerts_with_any_resource_pct']}%) "
            f"resources={blk['resource_entries_per_info']} "
            f"geocode_only_pct={blk['geocode_only_pct']} "
            f"CMAMtext={blk['alerts_with_CMAMtext']} "
            f"({blk['alerts_with_CMAMtext_pct']}%)"
        )
    line()
    line("-- SANITY CHECKS ------------------------------------------------------")
    for check in checks["checks"]:
        state = {True: "PASS", False: "FAIL", None: "INFO"}[check["passed"]]
        line(f"  [{state}] {check['id']}  {check['check']}")
        line(f"         {json.dumps(check['detail'], sort_keys=True)[:400]}")
    if checks["failed"]:
        line()
        line(f"WARNING: sanity checks failed: {', '.join(checks['failed'])}")
    else:
        line()
        line("All sanity checks passed (INFO entries are diagnostics, not assertions).")


# ----------------------------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--no-fetch",
        action="store_true",
        help="re-aggregate from --raw-dir without any network access",
    )
    parser.add_argument("--raw-dir", default=DEFAULT_RAW_DIR)
    parser.add_argument("--out", default=DEFAULT_OUT)
    parser.add_argument(
        "--no-verify-xml",
        action="store_true",
        help="skip refetching a sample with the raw CAP XML (check S8)",
    )
    parser.add_argument(
        "--no-context",
        action="store_true",
        help="skip the per-year dataset-composition counts",
    )
    args = parser.parse_args()

    manifest: dict | None = None
    if not args.no_fetch:
        manifest = fetch_window(
            args.raw_dir,
            do_context=not args.no_context,
            do_verify_xml=not args.no_verify_xml,
        )
    manifest_path = os.path.join(args.raw_dir, MANIFEST_NAME)
    if manifest is None and os.path.exists(manifest_path):
        with open(manifest_path) as handle:
            manifest = json.load(handle)

    records, load_report = load_raw(args.raw_dir)
    in_scope = [r for r in records if r.get("status") == STATUS_IN_SCOPE]
    excluded = len(records) - len(in_scope)

    agg = aggregate(in_scope)
    agg["subset_msgtype_alert"] = aggregate_subset(
        in_scope, lambda r: r.get("msgType") == "Alert"
    )
    agg["subset_real_events"] = aggregate_subset(
        in_scope,
        lambda r: (
            r.get("msgType") == "Alert"
            and not any(c in TEST_SAME_CODES for c in event_codes(r, "SAME"))
        ),
    )
    agg["by_originator_class"] = {
        "definition": (
            f"nws = sender '{NWS_SENDER}' (one federal machine-to-machine "
            "originator); non_nws = every other sender (state, local, tribal, "
            "territorial and other federal alerting authorities). The split is "
            "reported because originator practice differs on every dimension "
            "measured, so a single window-wide percentage can be dominated by "
            "one sender."
        ),
        "nws": aggregate_subset(in_scope, lambda r: r.get("sender") == NWS_SENDER),
        "non_nws": aggregate_subset(in_scope, lambda r: r.get("sender") != NWS_SENDER),
    }
    agg["subset_real_events"]["definition"] = (
        "msgType=Alert and no SAME eventCode in "
        + str(list(TEST_SAME_CODES))
        + ": first-issuance messages about real events only."
    )
    agg["excluded_records"] = {
        "records_loaded": len(records),
        "in_scope": len(in_scope),
        "excluded_non_actual": excluded,
    }
    checks = sanity_checks(in_scope, load_report, manifest, args.raw_dir)

    payload = {
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "script": os.path.basename(os.path.abspath(__file__)),
        "methodology": {
            "source_dataset": "OpenFEMA IPAWS Archived Alerts v1",
            "endpoint": ENDPOINT,
            "window_start": WINDOW_START,
            "window_end": WINDOW_END,
            "window_bound_note": (
                "half-open; end bound is 00:00Z of the run date, so "
                "'today' is excluded. FEMA publishes with a documented "
                "~24h delay, which leaves the last day inside the "
                "window partial: measured in sanity check S7."
            ),
            "status_in_scope": STATUS_IN_SCOPE,
            "counting_unit": (
                "one archived CAP message = one 'alert'. msgType Update and "
                "Cancel messages are separate records and are included; the "
                "subset_msgtype_alert block repeats the headline numbers on "
                "msgType=Alert only."
            ),
            "per_info_note": (
                "a CAP <info> block is per-language, so a bilingual message "
                "repeats its resource and parameter lists. Fields named "
                "*_per_info count info-level entries; everything else counts "
                "alert messages."
            ),
            "select_fields": SELECT_FIELDS,
            "originalMessage_excluded": (
                "excluded from the bulk fetch for size; a "
                "deterministic sample is refetched with it and "
                "cross-checked against the parsed fields (S8)."
            ),
            "media_classification": (
                "mimeType prefix (video/ image/ audio/ text/), with a "
                "URI-extension backstop reported separately so a "
                "mislabelled video cannot hide."
            ),
            "raw_dir": args.raw_dir,
            "rerun": (
                "python3 fetch_and_aggregate.py            # refetch + recompute\n"
                "python3 fetch_and_aggregate.py --no-fetch # recompute from raw dir"
            ),
        },
        "load_report": load_report,
        "sanity_checks": checks,
        "dataset_context": (manifest or {}).get("dataset_context"),
        "fetch_manifest_summary": {
            "fetched_at_utc": (manifest or {}).get("fetched_at_utc"),
            "window_total_from_api": (manifest or {}).get("window_total_from_api"),
            "pages": len((manifest or {}).get("pages") or []),
            "subwindows": (manifest or {}).get("subwindows"),
            "paging_strategy": (manifest or {}).get("paging_strategy"),
        },
        "aggregates": agg,
    }
    with open(args.out, "w") as handle:
        json.dump(stringify_keys(payload), handle, indent=1, sort_keys=True)
        handle.write("\n")

    print_report(agg, checks, load_report, manifest)
    print()
    print(f"aggregates written to {args.out}")
    print(f"raw pages in            {args.raw_dir}")
    return 1 if checks["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
