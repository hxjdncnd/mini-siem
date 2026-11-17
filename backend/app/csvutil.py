"""CSV export helpers.

Log fields are attacker-controlled (a username, a URL, a user agent), and spreadsheets treat a cell that
starts with = + - or @ as a formula. Exporting them verbatim would let an attacker run formulas on the
analyst's machine, so text cells that could be read as one get a leading apostrophe.
"""

import csv
import io
from collections.abc import Iterable, Iterator, Sequence
from datetime import datetime

_FORMULA_STARTS = ("=", "+", "-", "@", "\t", "\r")


def safe_cell(value: object) -> object:
    if value is None:
        return ""
    if isinstance(value, str) and value.startswith(_FORMULA_STARTS):
        return "'" + value
    return value


def iso(moment: datetime) -> str:
    return moment.isoformat().replace("+00:00", "Z")


def stream_csv(header: Sequence[str], rows: Iterable[Sequence[object]]) -> Iterator[str]:
    """Yield CSV text in chunks, so a large export never sits in memory all at once."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(header)
    for count, row in enumerate(rows, start=1):
        writer.writerow([safe_cell(cell) for cell in row])
        if count % 500 == 0:
            yield buffer.getvalue()
            buffer.seek(0)
            buffer.truncate()
    yield buffer.getvalue()
