"""Self-match masking for offline evaluation of the similarity layer.

The similarity layer scores a prompt against data/processed/known_attacks.jsonl,
which contains EVERY training positive. Any evaluation that draws its samples
from that same corpus therefore lets each prompt match itself at cosine 1.0,
which pins the layer at a perfect score and inflates the ensemble.

That is a measurement artifact, not a production behaviour: in production a
fresh request is not already in the corpus. Masking exists so evaluation asks
"what would this have scored had it never been seen", which is the question the
benchmark is for.

Masking is by id AND by normalised text. Id alone is not enough — the corpus is
built from overlapping public sources (Lakera / JailbreakBench / AdvBench) and
is never de-duplicated, so the same prompt can appear under two ids and match
its own twin at cosine 1.0 through the back door.

This module is deliberately free of model dependencies so it can be unit-tested
without weights.
"""

from __future__ import annotations

import numpy as np

# --- Constants ---
MASKED_VALUE = -np.inf  # survives .max(); clipped back to 0.0 by callers


def normalise(text: str) -> str:
    """Case- and whitespace-insensitive form used for duplicate detection."""
    return " ".join(text.split()).casefold()


def mask_self_matches(
    sims: np.ndarray,
    row_ids: list[str],
    row_texts: list[str],
    known_ids: list[str],
    known_texts: list[str],
) -> int:
    """Blank out each row's own corpus entry (and its duplicates) in-place.

    `sims` is (n_rows, n_known). `row_ids` / `row_texts` identify the corpus
    entry each row originates from — for a rewritten prompt, pass the id and
    text of the ORIGINAL it was derived from, so the rewrite is scored against
    everything except its own source.

    Returns the number of rows that had at least one column masked.
    """
    if sims.shape != (len(row_ids), len(known_ids)):
        raise ValueError(
            f"sims shape {sims.shape} does not match "
            f"({len(row_ids)} rows, {len(known_ids)} known)"
        )
    if len(row_ids) != len(row_texts):
        raise ValueError("row_ids and row_texts must be the same length")
    if len(known_ids) != len(known_texts):
        raise ValueError("known_ids and known_texts must be the same length")

    col_of_id = {kid: j for j, kid in enumerate(known_ids)}
    cols_of_text: dict[str, list[int]] = {}
    for j, text in enumerate(known_texts):
        cols_of_text.setdefault(normalise(text), []).append(j)

    rows_masked = 0
    for i, (row_id, row_text) in enumerate(zip(row_ids, row_texts)):
        cols = set(cols_of_text.get(normalise(row_text), ()))
        j = col_of_id.get(row_id)
        if j is not None:
            cols.add(j)
        if cols:
            sims[i, sorted(cols)] = MASKED_VALUE
            rows_masked += 1
    return rows_masked
