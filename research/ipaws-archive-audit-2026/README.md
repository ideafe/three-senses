# What one year of United States public alerts carried for people who cannot hear them

An archival audit by International Deaf Emergency (IDE), 2026. Author: Emmanuel Jacq.

The Common Alerting Protocol (CAP) lets an alerting authority attach a video, add a second language
and grade the urgency of an alert. This audit asks whether anyone does. It reads every message that
FEMA's public archive holds for one year and counts what each one carries.

## The result

Window: messages sent from 2025-08-20T00:00:00Z to 2026-08-20T00:00:00Z, read from the OpenFEMA
dataset "IPAWS Archived Alerts" version 1. Counts are those of `aggregates-2026-09-09.json`.

| Measure | Count | Share |
|---|---|---|
| Archived messages | 16,508 | |
| Distinct senders | 1,197 | |
| Messages with any attached resource | 2,539 | 15.38% of messages |
| Resource entries, counted per language block | 2,741 | |
| Audio entries | 2,691 | 98.18% of entries |
| Still image entries (on six alerts) | 22 | 0.80% of entries |
| Links to web pages | 25 | 0.91% of entries |
| Entries that could not be classified | 3 | 0.11% of entries |
| Video entries | 0 | |
| Entries whose description or address names a sign language | 0 | |
| Messages with a Spanish block | 7,025 | 42.56% of messages |
| Share of messages with Spanish among the 1,196 senders other than the one automated national sender | | 13.90% |

## What it does not show

- It counts messages, not people. It says nothing about what any Deaf or DeafBlind person received,
  understood or did.
- It covers one year and one country.
- The sign-language search reads the description and the address of each attached resource. It does
  not open the files. A signed video inside a file with an uninformative name would be missed.
- A signed video that an authority published elsewhere, for example on its own website, is not in
  this archive.
- FEMA describes the archive as raw and unvalidated. The script cross-checks a sample against the
  original CAP XML.

## Files

- `fetch_and_aggregate.py`: the analysis script (Python 3.12, standard library only). Every choice
  of method is a named constant at the top of the file: the window, the status filter, the media
  classification, the sign-language search patterns, the test event codes.
- `aggregates-2026-09-09.json`: the counts above, computed on 9 September 2026 from a fresh fetch
  of the window (16,508 records).
- `aggregates-2026-08-20.json`: an earlier snapshot of the same window, computed on 20 August 2026
  (16,456 records), kept for the stability check.
- `publishable.py`: makes the copy of a counts file that is published here (see below).

## Reproduce

```
python3 fetch_and_aggregate.py --raw-dir ./raw --out aggregates-rerun.json
```

This fetches about 22 pages of at most 1,000 records from the public OpenFEMA endpoint, with half a
second between requests, runs the sanity checks and writes the counts. Add `--no-fetch` to recompute
from saved raw pages without network access. The raw pages are not included: they can be fetched
again and take about 86 MB.

The OpenFEMA endpoint refuses requests from some data-centre address ranges with HTTP 403. A home
connection or a hosted CI runner works. This repository has a manual workflow for that, "Audit
re-run" (`.github/workflows/audit-rerun.yml`): it runs the script on a GitHub-hosted runner and
keeps the published copy of the counts as an artifact.

To count another period, set `IPAWS_AUDIT_WINDOW_START` and `IPAWS_AUDIT_WINDOW_END` (both on the
20th of a month at 00:00Z), or give the two bounds to the workflow. Without them the script counts
the published window.

## What is withheld in the published counts

The archive is public, but two things in it can point at persons, so the JSON files here are the
output of `publishable.py`, which differs from the script's own output in two places:

- the addresses of image files attached to alerts are withheld, because such a file may show a
  person;
- the sender identifiers in the list of the twenty largest senders are withheld, because some are
  a person's name. The one automated national sender, which the analysis names, is kept.

Each is replaced by a line that says so. Counts are untouched. The script reproduces the original
values from the public dataset.

## How this was made

The script and a first draft of the text were produced with AI tools, under the direction of the
author, who set the window, the counting units, the classification rules and the sanity checks. Every
count above is recomputed by the script from the public dataset. The window was fetched and counted
twice, on 20 August and on 9 September 2026.

## Licence and citation

The script is under the Apache License 2.0, like the code of this repository. The counts are facts
drawn from a public federal dataset.

Emmanuel Jacq, International Deaf Emergency. What one year of United States public alerts carried
for people who cannot hear them: an archival audit of the IPAWS archive, 2026.
https://github.com/ideafe/three-senses/tree/main/research/ipaws-archive-audit-2026
