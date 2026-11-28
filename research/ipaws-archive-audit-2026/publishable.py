#!/usr/bin/env python3
"""
Make a copy of an aggregates file that is fit to publish.

The source archive is public, but two things in the aggregates can point at persons:
the addresses of image files attached to alerts (such a file may show a person), and
sender identifiers, some of which are a person's name. This script withholds both:

  - every "uri" value in aggregates.multimedia.extension_video_or_image_but_other_mimetype;
  - every key of aggregates.originators.top_20_senders except the one automated national
    sender (NWS_SENDER), whose identifier is institutional and which the analysis names.

Counts are untouched. Usage:
    python3 publishable.py IN.json OUT.json
"""

from __future__ import annotations

import json
import sys

NWS_SENDER = "w-nws.webmaster@noaa.gov"
URI_LIST = "extension_video_or_image_but_other_mimetype"
NOTE = (
    "In this published copy, the addresses of image files and every sender identifier "
    "except the automated national sender are withheld. The script reproduces them from "
    "the public dataset."
)


def publishable(doc: dict) -> dict:
    agg = doc["aggregates"]
    for entry in agg["multimedia"].get(URI_LIST, []):
        if "uri" in entry:
            entry["uri"] = "[withheld: the file may show a person]"
    senders = agg["originators"]["top_20_senders"]
    out: dict = {}
    n = 0
    for key, value in senders.items():
        if key == NWS_SENDER:
            out[key] = value
        else:
            n += 1
            out[f"[withheld: sender identifier {n:02d}]"] = value
    agg["originators"]["top_20_senders"] = out
    doc["published_copy_note"] = NOTE
    return doc


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    with open(sys.argv[1], encoding="utf-8") as handle:
        doc = json.load(handle)
    with open(sys.argv[2], "w", encoding="utf-8") as handle:
        json.dump(publishable(doc), handle, indent=1, ensure_ascii=False)
        handle.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
