"""Gateway consumer never becomes a second design store or cross-pair editor."""
import subprocess
from pathlib import Path

from clusterctl.homes.styles import StyleConsumer
from clusterctl.homes.policy import Actor
from tests.test_home_gateway import Authority


def test_stable_being_scope_and_explicit_viewer_context_do_not_repaint_another_pairs_home():
    calls=[]
    class Provider:
        def resolve(self,subject,**fields):
            calls.append((subject,fields));return {'contract':'homemaker.resolved/v1','appearance':None}
    authority=Authority()
    consumer=StyleConsumer(Provider(),authority,{'one':{'owner_being_ref':'owner-one'}})
    consumer.resolved('one','home',authority.actor('human-one'))
    assert calls[-1]==('human-one',{'author':{'kind':'being','ref':'owner-one'},'surface':'home','viewer_scope':{'kind':'human','ref':'human-one'}})
    consumer.resolved('one','home',authority.actor('human-two'))
    assert calls[-1][1]['viewer_scope'] is None
    consumer.resolved('one','resource-ref')
    assert calls[-1][0] is None and calls[-1][1]['surface']=='resource-ref'
    old=authority.actor('human-one');authority.people['human-one']=Actor('human-one','human','v2','changed')
    consumer.resolved('one','home',old)
    assert calls[-1][0] is None
    assert not hasattr(consumer,'select') and not hasattr(consumer,'import_recipe')


def test_sandbox_style_consumer_rejects_forged_or_unsafe_payloads():
    subprocess.run(['node','--test','tests/js/home-style-client.cjs'],cwd=Path(__file__).resolve().parents[1],check=True)
