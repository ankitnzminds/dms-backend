"""Signature chains: levels, optional signers and the super signer (ported from the reference DMS).

Rules (all covered by tests)
  * Levels run in order; signers inside one level act in parallel.
  * A level is **complete** when every *required* (non-optional) signer in it has signed (or been
    bypassed). A level made only of optional signers needs at least one signature.
  * A signer may act only when their level is the active level or an earlier one (an optional signer
    of an already-finished level may still sign until the request ends).
  * A required signer who declines halts the chain: pending signers at that level and later levels
    are ``cancelled`` and the request becomes ``declined``. An optional signer who declines changes
    nothing else.
  * A super signer who signs fast-forwards: every other pending signer at their level and at later
    levels becomes ``bypassed`` and the request completes at once.
  * The request completes when the last level is complete; optional signers still pending are
    ``bypassed`` (their signature is no longer needed).
  * The chain is copied onto the request's recipients at creation, so editing the folder chain never
    changes a request that is already running.

Progress is computed from the recipients' statuses on every call (no "create next level" step), so a
repeated or concurrent action cannot advance the chain twice. Callers hold the request row lock.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from app.db.models import SignatureRecipient

BYPASS_REASON = "Bypassed - a super-signer signed and fast-forwarded the remaining chain"
HALT_REASON = "Signature chain halted - another signer at this level declined"
DONE_REASON = "Not needed - the signature chain completed without this optional signer"


@dataclass(frozen=True)
class ChainState:
    active_level: int | None  # None when the chain is complete or halted
    halted: bool
    complete: bool


def evaluate(recipients: Iterable[SignatureRecipient]) -> ChainState:
    recs = list(recipients)
    for level in sorted({r.level for r in recs}):
        at = [r for r in recs if r.level == level]
        required = [r for r in at if not r.optional]
        if any(r.status == "declined" for r in required):
            return ChainState(None, True, False)
        if required:
            done = all(r.status in ("signed", "bypassed") for r in required)
        else:
            done = any(r.status == "signed" for r in at)
        if not done:
            return ChainState(level, False, False)
    return ChainState(None, False, True)


def can_act(rec: SignatureRecipient, state: ChainState) -> bool:
    """Is this recipient's turn? (pending, and not waiting for an earlier level)"""
    return (
        rec.status == "pending"
        and state.active_level is not None
        and rec.level <= state.active_level
    )


def bypass_after_super(
    recs: Sequence[SignatureRecipient], signer: SignatureRecipient
) -> list[SignatureRecipient]:
    """Pending signers a super signer's signature fast-forwards past (same level and later levels)."""
    return [
        r for r in recs if r is not signer and r.status == "pending" and r.level >= signer.level
    ]


def halt_targets(
    recs: Sequence[SignatureRecipient], decliner: SignatureRecipient
) -> list[SignatureRecipient]:
    """Pending signers cancelled when a required signer declines (same level and later levels)."""
    return [
        r for r in recs if r is not decliner and r.status == "pending" and r.level >= decliner.level
    ]
