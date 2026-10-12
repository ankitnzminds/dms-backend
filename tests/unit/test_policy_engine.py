"""Policy engine core: validation grammar, group targeting, precedence and fail-closed behavior."""

from __future__ import annotations

import uuid

import pytest

from app.modules.policy_engine import evaluator as ev
from app.modules.policy_engine.schema import PolicyValidationError, parse_document

ORG_WIDE = {"type": "organization"}
G1, G2 = uuid.uuid4(), uuid.uuid4()


def doc(**over):  # noqa: ANN003, ANN201
    base = {
        "schema_version": 1,
        "effect": "DENY",
        "scope": ORG_WIDE,
        "resource_types": ["document"],
        "actions": ["download"],
    }
    base.update(over)
    return base


def rule(raw, n=1):  # noqa: ANN001, ANN201
    return ev.Rule(uuid.UUID(int=n), 1, parse_document(raw))


def ctx(
    *,
    role="member",
    groups=(),
    level="full",
    external=False,
    action="download",
    rtype="document",
    classification="confidential",
    chain=(),
    rid=None,
    ext="pdf",
    owner=False,
):
    subject = ev.Subject(uuid.uuid4(), role, frozenset(groups), level, external)
    resource = ev.Resource(rtype, rid or uuid.uuid4(), frozenset(chain), classification, ext, owner)
    return ev.EvalContext(subject, resource, action)


CONF = {"attribute": "resource.classification", "operator": "EQUALS", "value": "confidential"}


# ---- validation ---------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "bad",
    [
        doc(effect="REQUIRE_STEP_UP_AUTHENTICATION"),
        doc(effect="allow"),
        doc(actions=[]),
        doc(actions=["fly"]),
        doc(resource_types=["share"]),
        doc(unknown=1),
        doc(schema_version=2),
        doc(scope={"type": "folder"}),
        doc(scope={"type": "organization", "id": str(uuid.uuid4())}),
        doc(mandatory=True, effect="ALLOW"),
        doc(subjects={"groups": ["not-a-uuid"]}),
        doc(subjects={"roles": ["emperor"]}),
        doc(condition={"attribute": "resource.__class__", "operator": "EQUALS", "value": "x"}),
        doc(
            condition={"attribute": "resource.classification", "operator": "MATCHES", "value": "x"}
        ),
        doc(
            condition={
                "attribute": "resource.classification",
                "operator": "EQUALS",
                "value": "secret",
            }
        ),
        doc(
            condition={"attribute": "resource.classification", "operator": "IN", "value": "public"}
        ),
        doc(condition={"attribute": "resource.classification", "operator": "EXISTS", "value": "x"}),
        doc(condition={"attribute": "subject.is_external", "operator": "EQUALS", "value": "yes"}),
        doc(condition={"attribute": "subject.is_external", "operator": "IN", "value": [True]}),
        doc(condition={"op": "XOR", "conditions": [CONF]}),
        doc(condition={"op": "AND", "conditions": []}),
        doc(
            condition={
                "attribute": "resource.classification",
                "operator": "EQUALS",
                "value": "public",
                "x": 1,
            }
        ),
        # classification does not exist on folders
        doc(resource_types=["document", "folder"], condition=CONF),
    ],
)
def test_invalid_documents_are_rejected(bad):  # noqa: ANN001
    with pytest.raises(PolicyValidationError) as e:
        parse_document(bad)
    assert e.value.issues


def test_depth_and_size_limits():
    node = CONF
    for _ in range(6):
        node = {"op": "AND", "conditions": [node]}
    with pytest.raises(PolicyValidationError):
        parse_document(doc(condition=node))
    wide = {"op": "OR", "conditions": [CONF] * 30}
    with pytest.raises(PolicyValidationError):
        parse_document(doc(condition=wide))


def test_non_object_is_rejected():
    for bad in (None, [], "DENY", 7):
        with pytest.raises(PolicyValidationError):
            parse_document(bad)


# ---- evaluation: effects ------------------------------------------------------------------------
def test_no_rules_means_no_opinion_never_a_grant():
    d = ev.evaluate([], ctx())
    assert d.outcome == "no_opinion" and d.reason == ev.NO_OPINION


def test_deny_matches_on_condition_and_subject():
    r = rule(doc(subjects={"access_levels": ["external"]}, condition=CONF))
    assert ev.evaluate([r], ctx(level="external")).reason == ev.DENY
    assert ev.evaluate([r], ctx(level="full")).outcome == "no_opinion"
    assert ev.evaluate([r], ctx(level="external", classification="public")).outcome == "no_opinion"
    assert ev.evaluate([r], ctx(level="external", action="preview")).outcome == "no_opinion"


def test_require_approval_effect():
    r = rule(doc(effect="REQUIRE_APPROVAL", actions=["share"], condition=CONF))
    d = ev.evaluate([r], ctx(action="share"))
    assert d.outcome == "require_approval" and d.reason == ev.APPROVAL_REQUIRED


def test_allow_never_lifts_a_deny_or_approval():
    deny = rule(doc(condition=CONF), 1)
    allow = rule(doc(effect="ALLOW"), 2)
    d = ev.evaluate([deny, allow], ctx())
    assert d.outcome == "deny" and len(d.allow_matched) == 1
    appr = rule(doc(effect="REQUIRE_APPROVAL"), 3)
    assert ev.evaluate([appr, allow], ctx()).outcome == "require_approval"
    # a lone ALLOW is explanation only: it grants nothing
    assert ev.evaluate([allow], ctx()).outcome == "no_opinion"


# ---- precedence ---------------------------------------------------------------------------------
def test_mandatory_deny_beats_everything_and_approval_cannot_bypass_deny():
    mand = rule(doc(mandatory=True), 1)
    deny = rule(doc(), 2)
    appr = rule(doc(effect="REQUIRE_APPROVAL"), 3)
    assert ev.evaluate([appr, deny, mand], ctx()).reason == ev.MANDATORY_DENY
    assert ev.evaluate([appr, deny], ctx()).reason == ev.DENY
    assert ev.evaluate([appr, deny], ctx()).outcome != "require_approval"


def test_every_match_is_reported_and_order_is_irrelevant():
    rs = [rule(doc(), n) for n in (5, 2, 9)]
    a = ev.evaluate(rs, ctx())
    b = ev.evaluate(list(reversed(rs)), ctx())
    assert a == b or (a.reason == b.reason and a.matched == b.matched)
    assert [m.policy_id.int for m in a.matched] == [2, 5, 9]


# ---- fail closed --------------------------------------------------------------------------------
def test_missing_context_fails_closed_for_deny_but_not_for_allow():
    r = rule(doc(condition=CONF))
    assert ev.evaluate([r], ctx(classification=None)).reason == ev.CONTEXT_MISSING
    # NOT_EQUALS on unknown must not accidentally satisfy a restriction either
    neq = rule(doc(condition={**CONF, "operator": "NOT_EQUALS", "value": "public"}))
    assert ev.evaluate([neq], ctx(classification=None)).denied
    allow = rule(doc(effect="ALLOW", condition=CONF))
    assert ev.evaluate([allow], ctx(classification=None)).outcome == "no_opinion"


def test_exists_and_not_exists_are_explicit_about_missing():
    ex = rule(doc(condition={"attribute": "resource.file_extension", "operator": "NOT_EXISTS"}))
    assert ev.evaluate([ex], ctx(ext=None)).reason == ev.DENY
    assert ev.evaluate([ex], ctx(ext="pdf")).outcome == "no_opinion"


# ---- operators ----------------------------------------------------------------------------------
def test_in_not_in_and_or_and_case_insensitivity():
    inn = rule(
        doc(
            condition={
                "attribute": "resource.file_extension",
                "operator": "IN",
                "value": ["PDF", "docx"],
            }
        )
    )
    assert ev.evaluate([inn], ctx(ext="pdf")).denied
    assert not ev.evaluate([inn], ctx(ext="png")).denied
    nin = rule(
        doc(
            condition={
                "attribute": "resource.file_extension",
                "operator": "NOT_IN",
                "value": ["pdf"],
            }
        )
    )
    assert ev.evaluate([nin], ctx(ext="png")).denied
    both = rule(
        doc(
            condition={
                "op": "AND",
                "conditions": [
                    CONF,
                    {"attribute": "subject.is_external", "operator": "EQUALS", "value": True},
                ],
            }
        )
    )
    assert ev.evaluate([both], ctx(external=True)).denied
    assert not ev.evaluate([both], ctx(external=False)).denied
    either = rule(
        doc(
            condition={
                "op": "OR",
                "conditions": [
                    CONF,
                    {"attribute": "subject.is_external", "operator": "EQUALS", "value": True},
                ],
            }
        )
    )
    assert ev.evaluate([either], ctx(external=True, classification="public")).denied


# ---- groups -------------------------------------------------------------------------------------
def test_group_policy_applies_to_every_member_and_only_members():
    r = rule(doc(subjects={"groups": [str(G1)]}))
    assert ev.evaluate([r], ctx(groups=[G1])).denied
    assert ev.evaluate([r], ctx(groups=[G1, G2])).denied  # member of several groups
    assert not ev.evaluate([r], ctx(groups=[G2])).denied
    assert not ev.evaluate(
        [r], ctx(groups=[])
    ).denied  # removed from the group -> no longer applies


def test_conflicting_group_policies_deny_wins_deterministically():
    r1 = rule(doc(effect="REQUIRE_APPROVAL", subjects={"groups": [str(G1)]}), 1)
    r2 = rule(doc(subjects={"groups": [str(G2)]}), 2)
    both = ctx(groups=[G1, G2])
    assert ev.evaluate([r1, r2], both).outcome == "deny"
    assert ev.evaluate([r2, r1], both) == ev.evaluate([r1, r2], both)
    assert ev.evaluate([r1, r2], ctx(groups=[G1])).outcome == "require_approval"


def test_subject_targets_are_a_union():
    uid = uuid.uuid4()
    r = rule(doc(subjects={"users": [str(uid)], "roles": ["auditor"]}))
    c = ctx(role="auditor")
    assert ev.evaluate([r], c).denied
    assert not ev.evaluate([r], ctx(role="member")).denied


# ---- resource scope -----------------------------------------------------------------------------
def test_folder_scope_covers_subtree_and_file_scope_one_document():
    fid, did = uuid.uuid4(), uuid.uuid4()
    folder_rule = rule(
        doc(scope={"type": "folder", "id": str(fid)}, resource_types=["document", "folder"])
    )
    assert ev.evaluate([folder_rule], ctx(chain=[uuid.uuid4(), fid])).denied
    assert not ev.evaluate([folder_rule], ctx(chain=[uuid.uuid4()])).denied
    file_rule = rule(doc(scope={"type": "file", "id": str(did)}))
    assert ev.evaluate([file_rule], ctx(rid=did)).denied
    assert not ev.evaluate([file_rule], ctx()).denied


def test_every_predefined_template_is_valid_and_unique():
    from app.modules.policy_engine.templates import catalogue

    keys = [t.key for t in catalogue()]
    assert len(keys) == len(set(keys)) >= 5
    for t in catalogue():
        parse_document(t.document)  # raises if a shipped template would not publish
        assert t.purpose and t.category
    # the only approval template must say it cannot be enforced
    appr = next(t for t in catalogue() if t.document["effect"] == "REQUIRE_APPROVAL")
    assert appr.requires and "observe" in " ".join(appr.limitations).lower()


def test_grammar_endpoint_mirrors_the_validator():
    from app.modules.policy_engine import schema as s
    from app.modules.policy_engine.templates import grammar

    g = grammar()
    assert {a.name for a in g.attributes} == set(s.ATTRIBUTES)
    assert "REQUIRE_STEP_UP_AUTHENTICATION" in g.unsupported_effects
    assert "administer" not in g.actions and "download" in g.actions
    bool_attr = next(a for a in g.attributes if a.kind == "bool")
    assert "IN" not in bool_attr.operators
