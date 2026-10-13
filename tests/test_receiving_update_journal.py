"""Receiving update intent cannot substitute or replay retained selection vectors."""
import copy

import pytest

from clusterctl.onboarding import OnboardingError
from clusterctl.onboarding_code_successor import plan_update
from clusterctl.operation_journal import JournalConflict, OperationJournal


def fixture(tmp_path):
    journal = OperationJournal(tmp_path / 'state')
    arguments = dict(manifest_digest='a' * 64, target='receiving:synthetic-cohort',
        expected_precondition={'roster': 'b' * 64, 'receivers': {'one': 'c' * 64}},
        intended_transition={'roster': 'b' * 64, 'receivers': {'one': 'd' * 64}},
        audit_identity={'actor': 'synthetic-owner'})
    return journal, arguments


def test_exact_prepare_and_completed_retry_use_the_same_actual_journal_row(tmp_path):
    journal, arguments = fixture(tmp_path)
    first = plan_update(journal, **arguments)
    second = plan_update(journal, **copy.deepcopy(arguments))
    assert first == second and first['state'] == 'planned'
    assert len(journal.list_all()) == 1
    assert first['expected_precondition'] == arguments['expected_precondition']
    journal.advance(first['operation_id'], 'completed', result={'synthetic': True})
    complete = plan_update(journal, **arguments)
    assert complete['operation_id'] == first['operation_id']
    assert complete['state'] == 'completed' and len(journal.list_all()) == 1


@pytest.mark.parametrize('field', ['expected_precondition', 'intended_transition'])
@pytest.mark.parametrize('state', ['planned', 'runtime-dispatching', 'completed'])
def test_altered_vectors_cannot_change_or_reuse_a_retained_operation(tmp_path, field, state):
    journal, arguments = fixture(tmp_path)
    first = plan_update(journal, **arguments)
    journal.advance(first['operation_id'], state)
    changed = copy.deepcopy(arguments)
    changed[field]['receivers']['one'] = 'e' * 64
    before = journal.get(first['operation_id'])
    with pytest.raises(JournalConflict, match='different exact selection vectors'):
        plan_update(journal, **changed)
    assert journal.get(first['operation_id']) == before
    assert len(journal.list_all()) == 1


def test_changed_manifest_cannot_replace_pending_cohort_and_inputs_are_not_aliases(tmp_path):
    journal, arguments = fixture(tmp_path)
    first = plan_update(journal, **arguments)
    changed = {**arguments, 'manifest_digest': 'e' * 64}
    with pytest.raises(JournalConflict, match='pending, contradictory'):
        plan_update(journal, **changed)
    arguments['expected_precondition'].clear()
    first['intended_transition'].clear()
    stored = journal.get(first['operation_id'])
    assert stored['expected_precondition']['roster'] == 'b' * 64
    assert stored['intended_transition']['receivers']['one'] == 'd' * 64
    assert len(journal.list_all()) == 1


def test_invalid_intent_is_refused_before_journal_mutation(tmp_path):
    journal, arguments = fixture(tmp_path)
    for changes in ({'manifest_digest': 'not-qualified'}, {'target': 'target with spaces'},
                    {'expected_precondition': []}, {'intended_transition': None}):
        with pytest.raises(OnboardingError, match='invalid_receiving_update_intent'):
            plan_update(journal, **{**arguments, **changes})
    assert journal.list_all() == []


@pytest.mark.parametrize('state', ['degraded', 'compensated'])
def test_retry_cannot_rearm_degraded_or_compensated_update(tmp_path, state):
    journal, arguments = fixture(tmp_path)
    first = plan_update(journal, **arguments)
    journal.advance(first['operation_id'], state)
    before = journal.get(first['operation_id'])
    with pytest.raises(JournalConflict, match='explicit repair'):
        plan_update(journal, **arguments)
    assert journal.get(first['operation_id']) == before
