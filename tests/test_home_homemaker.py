"""Receiving identity/permission and public-source boundaries for Homemaker."""
from dataclasses import replace
from http.client import HTTPConnection
from urllib.parse import urlsplit
import pytest

from clusterctl.homes.homemaker import Homemaker
from clusterctl.homes.service import handler
from tests.test_home_gateway import serving
from tests.test_home_passkeys import system, approved


def receiving(app):
    provider=Homemaker.__new__(Homemaker)
    provider.app=app
    provider.templates={'world':'Existing source world'}
    return provider


def test_current_pair_permission_is_separate_from_visiting_another_home(system):
    app, _=system;provider=receiving(app)
    token,_=approved(app,home='two',actor='human')
    visitor=app.identity(token,'two',app.homes['two']['public_url'])
    assert visitor.ref=='human'
    with pytest.raises(ValueError,match='denied'):provider.scope('two',visitor,'pair')
    assert provider.scope('two',visitor,'personal')[0]=={'kind':'human','ref':'human'}
    assert provider.scope('one',visitor,'pair')[0]=={'kind':'being','ref':'owner'}
    app.authority.people['human']=replace(visitor,revision='changed')
    with pytest.raises(ValueError,match='denied'):provider.scope('one',visitor,'pair')


def test_reading_identity_does_not_authorize_another_persons_design_scope(system):
    app,_=system;provider=receiving(app)
    assert provider.authorize('human','design.select',{'kind':'human','ref':'human'})
    assert not provider.authorize('human','design.update',{'kind':'human','ref':'other'})
    assert not provider.authorize('unknown','design.update',{'kind':'being','ref':'owner'})
    assert not provider.authorize('human','unrecognized.action',{'kind':'being','ref':'owner'})
    assert provider.authorize('owner','design.read',{'kind':'being','ref':'owner'})
    assert not provider.authorize('owner','design.update',{'kind':'being','ref':'owner'})


def test_request_cannot_replace_author_or_private_public_decision(system):
    app,_=system;provider=receiving(app);person=app.authority.actor('human')
    payload={'variant':'template-world','recipe':{},'expected_design_revision':0,
             'expected_selection_revision':0,'operation_id':'one'}
    for key in ('actor','owner','audience'):
        with pytest.raises(ValueError,match='invalid_design_save'):
            provider.save('one',person,'pair',{**payload,key:'chosen-by-request'})
    with pytest.raises(ValueError,match='mismatch'):provider.save('one',person,'pair',payload)
    with pytest.raises(ValueError,match='invalid_design_variant'):provider.variant('../private')


def test_canonical_source_asset_route_cannot_reach_backend_state_or_symlinks(tmp_path):
    provider=Homemaker.__new__(Homemaker);provider.public=tmp_path/'dist';provider.public.mkdir()
    (provider.public/'app.js').write_text('public source')
    private=tmp_path/'state';private.write_text('not public')
    (provider.public/'shortcut.js').symlink_to(private)
    assert provider.asset('app.js').read_text()=='public source'
    for name in ('../state','shortcut.js','/app.js','./app.js','.private','a/../app.js'):
        with pytest.raises(ValueError):provider.asset(name)


def test_anonymous_editor_offers_shared_login_without_loading_identity_or_design(system):
    app,_=system;app.designs=receiving(app)
    with serving(handler(app)) as base:
        conn=HTTPConnection(urlsplit(base).netloc)
        conn.request('GET','/homemaker/',headers={'Host':'one.example.test'})
        response=conn.getresponse();body=response.read()
        assert response.status==200 and b'Sign in' in body and b'Tu taller' in body
        assert b'bootstrap.js' not in body and b'owner' not in body
        conn.request('GET','/homemaker/api/context',headers={'Host':'one.example.test'})
        response=conn.getresponse();response.read();assert response.status==404
        conn.close()


def test_design_post_requires_current_browser_and_origin_not_null_or_bearer(system):
    app,_=system;app.designs=receiving(app);token,_=approved(app)
    with serving(handler(app)) as base:
        conn=HTTPConnection(urlsplit(base).netloc)
        for extras in ({'Origin':'null'},{'Origin':'https://two.example.test'},
                       {'Origin':'https://one.example.test','Authorization':'Bearer '+token}):
            conn.request('POST','/homemaker/api/default',body='{}',headers={
                'Host':'one.example.test','Cookie':'__Host-home='+token,**extras})
            response=conn.getresponse();response.read();assert response.status==403
        conn.close()
