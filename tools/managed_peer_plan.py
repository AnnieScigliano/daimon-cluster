"""Prepare an explicitly requested temporary peer repair using existing grants.

No custody, network, service changes or signed events are created here. The
membership-based group remains the canonical same-Tribe onboarding path.
"""
from __future__ import annotations
import copy
import hashlib
import json
import time
import uuid
from pathlib import Path
from daimon_matrix import relationships as rel
from daimon_matrix.canonical import canonical_bytes, b64url
from daimon_matrix.relationship_store import RelationshipView
from daimon_matrix.runtime import verify_relationship_card_authority
from daimon_matrix.weave import verify_event


def make_plan(tool, identities, supporting_identity, prior, template, endpoints):
    authorities = [tool.verify_identity(p) for p in identities]
    support = tool.verify_identity(supporting_identity)
    by_being = {a.state.being_ref:a for a in [*authorities,support]}
    beings = [a.state.being_ref for a in authorities]
    assert len(by_being) == 3 and len(set(beings)) == 2
    for event in prior:
        verify_event(event, by_being[event['being_ref']])
    now = time.time_ns() // 1000000
    view = RelationshipView(prior,at_ms=now,card_verifier=lambda c,t:
        verify_relationship_card_authority(c,by_being[c['being_ref']],at_ms=t))
    parents=[]
    for being in beings:
        candidates=[row['grant'] for row in view.grants.values() if row['state']=='active'
            and row['grant']['payload']['subject_being_ref']==being
            and any(p['classification']=='shareable' and 'messaging.read' in p['operations']
                and p['delegable'] and p['remaining_delegation_depth']>=1
                for p in row['grant']['payload']['permissions'])]
        assert candidates, 'No existing delegable messaging permission'
        parents.append(max(candidates,key=lambda e:e['occurred_at_ms']))
    resources=[{p['resource_ref'] for p in parent['payload']['permissions']
        if p['classification']=='shareable' and 'messaging.read' in p['operations']
        and p['delegable'] and p['remaining_delegation_depth']>=1} for parent in parents]
    common=resources[0]&resources[1];assert len(common)==1
    resource=next(iter(common))
    cards=[view.cards[b]['current'] for b in beings];assert all(cards)
    heads=[p['document']['ledger_head'] for p in identities]
    sequences=[h['max_sequence'] if h else 0 for h in heads]
    previous=[h['tip_event_id'] if h else None for h in heads]
    events=[]
    def ref(e):return {'event_id':e['event_id'],'event_hash':e['content_hash']}
    def nonce():return b64url(uuid.uuid4().bytes+uuid.uuid4().bytes)
    def append(actor,kind,payload):
        payload=rel.validate_relationship_event_payload(kind,payload,
            author_being_ref=beings[actor],causal_parents=())
        sequences[actor]+=1
        core=dict(protocol=tool.PROTOCOL,event_id=str(uuid.uuid4()),being_ref=beings[actor],
            manifest_hash=authorities[actor].manifest.digest,origin=identities[actor]['document']['origin'],
            sequence=sequences[actor],previous_event_id=previous[actor],occurred_at_ms=now,
            causal_parents=[],kind=kind,subject=rel.relationship_event_subject(kind,payload),
            payload=payload,supersedes=None,sensitivity='shareable')
        e={**core,'content_hash':hashlib.sha256(canonical_bytes(core)).hexdigest()}
        previous[actor]=e['event_id'];events.append(e);return e
    validity={'mode':'until-revoked','not_before_ms':now}
    permission=dict(resource_ref=resource,operations=['messaging.read'],classification='shareable',
        delegable=False,remaining_delegation_depth=0)
    relationship_nonce=nonce();relationship=rel.relationship_id(nonce=relationship_nonce,
        initiator_being_ref=beings[0],responder_being_ref=beings[1])
    offer=append(0,'matrix/relationship-offer',dict(schema='dm.relationship.offer/v2',
        relationship_id=relationship,nonce=relationship_nonce,initiator_being_ref=beings[0],
        responder_being_ref=beings[1],initiator_card_ref=ref(cards[0]),responder_card_ref=ref(cards[1]),
        terms_ref='dm:terms:v1:human-requested-chat-telegram-mirror',roles=['peer'],
        proposed_grants=[dict(grantor_being_ref=beings[0],subject_being_ref=beings[1],
            permissions=[permission],validity=validity)],issued_at_ms=now,expires_at_ms=now+7*86400000))
    append(1,'matrix/relationship-acceptance',dict(schema='dm.relationship.acceptance/v2',
        relationship_id=relationship,offer_ref=ref(offer),initiator_being_ref=beings[0],
        responder_being_ref=beings[1],initiator_card_ref=ref(cards[0]),responder_card_ref=ref(cards[1]),
        accepted_at_ms=now))
    tribe = None
    grants=[]
    for actor,parent in enumerate(parents):
        siblings=[row['grant'] for row in view.grants.values() if row['state']=='active'
            and row['grant']['payload']['parent_grant_ref']==ref(parent)]
        last=max(siblings,key=lambda e:e['payload']['delegation_sequence']) if siblings else None
        grant_nonce=nonce()
        grant=append(actor,'matrix/relationship-grant',dict(schema='dm.relationship.grant/v2',
            grant_id=rel.grant_id(nonce=grant_nonce,relationship=relationship,
                grantor_being_ref=beings[actor],subject_being_ref=beings[1-actor]),nonce=grant_nonce,
            relationship_id=relationship,tribe_ref=tribe,grantor_being_ref=beings[actor],
            subject_being_ref=beings[1-actor],permissions=[permission],validity=validity,
            issued_at_ms=now,parent_grant_ref=ref(parent),delegation_sequence=last['payload']['delegation_sequence']+1 if last else 0,
            previous_delegation_event_id=last['event_id'] if last else None))
        append(1-actor,'matrix/relationship-grant-acceptance',dict(schema='dm.relationship.grant-acceptance/v2',
            grant_id=grant['payload']['grant_id'],grant_ref=ref(grant),relationship_id=relationship,
            grantor_being_ref=beings[actor],subject_being_ref=beings[1-actor],accepted_at_ms=now))
        grants.append(grant)
    return dict(schema=tool.LINK_SCHEMA,link_id=str(uuid.uuid4()),created_at_ms=now,expires_at_ms=now+7*86400000,
        identities=identities,base_heads=heads,prior_cards=prior,events=events,endpoints=endpoints,
        destination=copy.deepcopy(template['destination']),tribe_ref=tribe,relationship_id=relationship,
        resource_ref=resource,membership_event=None,grant_events=[e['event_id'] for e in grants],
        mode='human-request-only',supporting_identity=supporting_identity,temporary_repair=True)
