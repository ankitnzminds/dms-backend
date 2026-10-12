"""Signature chain rules (pure): levels, optional signers, super signer, halting."""

from __future__ import annotations

from app.db.models import SignatureRecipient
from app.modules.signatures import chain


def rec(level, status="pending", optional=False, sup=False):  # noqa: ANN001, ANN201
    return SignatureRecipient(level=level, status=status, optional=optional, is_super_signer=sup)


def test_single_level_needs_every_required_signer():
    a, b = rec(1), rec(1)
    assert chain.evaluate([a, b]).active_level == 1
    a.status = "signed"
    assert chain.evaluate([a, b]).active_level == 1
    b.status = "signed"
    assert chain.evaluate([a, b]).complete


def test_levels_run_in_order():
    a, b, c = rec(1), rec(2), rec(3)
    assert chain.evaluate([a, b, c]).active_level == 1
    a.status = "signed"
    assert chain.evaluate([a, b, c]).active_level == 2
    b.status = "signed"
    assert chain.evaluate([a, b, c]).active_level == 3
    c.status = "signed"
    assert chain.evaluate([a, b, c]).complete


def test_optional_signers_do_not_block_a_level():
    req, opt, nxt = rec(1), rec(1, optional=True), rec(2)
    req.status = "signed"
    state = chain.evaluate([req, opt, nxt])
    assert state.active_level == 2 and opt.status == "pending"


def test_a_level_of_only_optional_signers_needs_at_least_one_signature():
    o1, o2, nxt = rec(1, optional=True), rec(1, optional=True), rec(2)
    assert chain.evaluate([o1, o2, nxt]).active_level == 1
    o1.status = "declined"
    assert chain.evaluate([o1, o2, nxt]).active_level == 1  # still nobody signed
    o2.status = "signed"
    assert chain.evaluate([o1, o2, nxt]).active_level == 2


def test_required_decline_halts_but_optional_decline_does_not():
    r, o = rec(1), rec(1, optional=True)
    o.status = "declined"
    assert not chain.evaluate([r, o]).halted
    r.status = "declined"
    s = chain.evaluate([r, o])
    assert s.halted and s.active_level is None and not s.complete


def test_only_the_active_or_an_earlier_level_may_act():
    a, b, early_opt = rec(1), rec(2), rec(1, optional=True)
    state = chain.evaluate([a, b, early_opt])
    assert chain.can_act(a, state) and not chain.can_act(b, state)
    a.status = "signed"
    state = chain.evaluate([a, b, early_opt])
    assert chain.can_act(b, state)
    assert chain.can_act(early_opt, state)  # an optional signer of a finished level may still sign
    b.status = "signed"
    assert not chain.can_act(early_opt, chain.evaluate([a, b, early_opt]))  # request is over


def test_super_signer_and_halt_target_selection():
    s = rec(2, sup=True)
    same, later, earlier, done = rec(2), rec(3), rec(1, optional=True), rec(3, status="signed")
    recs = [s, same, later, earlier, done]
    assert set(map(id, chain.bypass_after_super(recs, s))) == {id(same), id(later)}
    assert set(map(id, chain.halt_targets(recs, same))) == {id(s), id(later)}
