"""Execute the browser bridge against forged and version-pinned media messages."""
from pathlib import Path
import shutil
import subprocess

import pytest


def test_bridge_download_is_frame_origin_manifest_and_version_bound():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required to execute the browser bridge fixture")
    source = Path(__file__).resolve().parents[1] / "clusterctl/homes/assets/work-view.js"
    fixture = r'''
const fs=require('fs'), vm=require('vm'), assert=require('assert');
const child={}, listeners={}, clicks=[];
const file='media/'+'e'.repeat(64)+'.wav';
const root='/works/'+'a'.repeat(32)+'/'+'b'.repeat(64)+'/';
const frame={contentWindow:child,addEventListener(){},dataset:{src:'https://content.example/r/selected/index.html',downloadRoot:root,downloadFiles:JSON.stringify([file])},src:''};
const context={URL,location:{hash:'',pathname:'/view/selected',search:'?display=work'},history:{replaceState(){}},
document:{querySelector:()=>frame,body:{append(){}},createElement:()=>({click(){clicks.push(this.href)},remove(){}})},
window:{addEventListener:(name,callback)=>listeners[name]=callback}};
vm.runInNewContext(fs.readFileSync(process.argv[1],'utf8'),context);
function send(path,source=child,origin='null'){listeners.message({source,origin,data:{type:'home-artifact:download',path}})}
send(file); assert.deepStrictEqual(clicks,[root+file]);
for(const path of ['../secret', 'https://evil.example/'+file, 'media/'+'f'.repeat(64)+'.wav', file+'?resource=other', file+'#fragment', 'media/%2e%2e/secret'])send(path);
send(file,{},'null'); send(file,child,'https://content.example');
assert.strictEqual(clicks.length,1);
frame.dataset.downloadRoot='https://evil.example/'; send(file);
frame.dataset.downloadRoot='/works/'+'c'.repeat(32)+'/current/'; send(file);
assert.strictEqual(clicks.length,1);
frame.dataset.downloadRoot=root;frame.dataset.downloadFiles='not JSON';send(file);
assert.strictEqual(clicks.length,1);
'''
    subprocess.run([node,"-e",fixture,str(source)],check=True,capture_output=True,text=True)
