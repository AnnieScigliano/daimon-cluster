"""Real owner HTTP adapter + maintained publisher + canonical creator; no live writes."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from clusterctl.homes.homemaker import Homemaker
from clusterctl.homes.service import handler
from clusterctl.homes.styles import StyleConsumer
from tests.test_home_gateway import serving
from tests.test_home_passkeys import approved
from tools.qualify_home_login_browser import gateway


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--source',required=True);parser.add_argument('--helper',required=True)
    parser.add_argument('--out',required=True);args=parser.parse_args()
    spec=importlib.util.spec_from_file_location('selected_home_helper',args.helper)
    helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
    source=Path(args.source)
    with tempfile.TemporaryDirectory(prefix='native-style-owner-') as directory:
        with gateway(Path(directory)) as app:
            app.designs=Homemaker(app,source,Path(directory)/'designs')
            app.styles=StyleConsumer(app.designs,app.authority,app.homes)
            key=Path(directory)/'owner.key';key.write_text('fixture-owner');key.chmod(0o600)
            app.homes['one']['owner_token_file']=str(key)
            app.sessions.register_owner(home='one',actor='owner',revision='v1',token='fixture-owner')
            with serving(handler(app,owner=True)) as endpoint:
                binding={'access':{'home_ref':'one','owner_url':endpoint,'owner_token_file':str(key)}}
                def call(operation,**values):
                    return helper.style_request(binding,SimpleNamespace(command=operation,**values))
                recipe=json.loads((source/'examples/shared-home/tricorder.design.json').read_text())
                recipe_path=Path(directory)/'selected.design.json';recipe_path.write_text(json.dumps(recipe))
                baseline=call('style-baseline',variant='template-tricorder')
                save={'variant':'template-tricorder','recipe':str(recipe_path),'audience':'public',
                      'expected_design_revision':baseline['design_revision'],
                      'expected_selection_revision':baseline['selection_revision'],'operation_id':'native-default-one'}
                first=call('style-default',**save)
                assert call('style-default',**save)==first
                recovered=call('style-recipe',design_ref=first['design_ref'],design_revision=None)
                assert recovered['recipe']['config']==recipe['config']
                assert 'actor' not in recovered and 'owner' not in recovered
                pinned=call('style-select',surface='homemaker',default=False,design_ref=first['design_ref'],
                            design_revision=1,expected_revision=0,operation_id='native-pin')
                assert call('style-selection',surface='homemaker')==pinned
                # Editing a followed design updates default consumers, preserving the pin.
                recipe['config']['paletteId']='paper';recipe_path.write_text(json.dumps(recipe))
                second=call('style-default',**{**save,'expected_design_revision':1,
                    'expected_selection_revision':1,'operation_id':'native-edit'})
                assert second['design_ref']==first['design_ref'] and second['design_revision']==2
                home=app.styles.resolved('one','home');mini=app.styles.resolved('one','homemaker')
                assert home['appearance']!=mini['appearance'] and mini['design_revision']==1
                for packet,code in ((save,'design_operation_conflict'),
                        ({**save,'expected_selection_revision':2,'operation_id':'stale-design'},'design_revision_conflict'),
                        ({**save,'expected_design_revision':2,'operation_id':'stale-selection'},'design_selection_conflict')):
                    try:call('style-default',**packet)
                    except ValueError as error:assert str(error)==code
                    else:raise AssertionError('conflict_not_reported')
                call('style-select',surface='homemaker',default=True,design_ref=None,design_revision=None,
                     expected_revision=1,operation_id='native-return-default')
                assert app.styles.resolved('one','homemaker')['appearance']==home['appearance']
                # A native owner can neither substitute an actor/scope nor fetch another human's private recipe.
                private=app.designs.authority.save_design('other',owner={'kind':'human','ref':'other'},
                    identifier='private',name='Private fixture',recipe=recipe,audience='private',expected_revision=0,
                    operation_id='private-fixture')
                for operation,payload in (
                    ('style-recipe',{'design_ref':private['ref']}),
                    ('style-selection',{'surface':'foreign-resource'}),
                    ('style-select',{'surface':'home','scope':{'kind':'human','ref':'other'},
                                    'selection':{'mode':'default'},'expected_revision':0,'operation_id':'foreign-scope'})):
                    try:helper.owner_request(binding,operation,payload)
                    except ValueError:pass
                    else:raise AssertionError('foreign_scope_accepted')
                reader,_=approved(app,actor='owner');reader_key=Path(directory)/'reader.key'
                reader_key.write_text(reader);reader_key.chmod(0o600)
                try:helper.owner_request({'access':{**binding['access'],'owner_token_file':str(reader_key)}},
                                         'style-selection',{'surface':'home'})
                except ValueError:pass
                else:raise AssertionError('reader_elevated')
            receipt={'fixture':'actual creator canonical authority + owner HTTP + selected maintained helper',
                     'save_exact_retry':'same receipt and revision','recipe_read':'permitted bounded projection',
                     'followed_edit':'home advanced','explicit_pin':'MiniApp stayed on revision1',
                     'return_to_default':'same current appearance','conflicts':'stable409 codes',
                     'privacy':'foreign scope/resource/private recipe and reader credential denied',
                     'live_mutations':False,'phone_acceptance':False}
            out=Path(args.out);out.parent.mkdir(parents=True,exist_ok=True)
            out.write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt))

if __name__=='__main__':main()
