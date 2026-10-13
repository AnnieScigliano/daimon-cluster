const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),test=require('node:test');
const appearance={background:'#080b14',surface:'#080b14',text:'#eeeaf6',accent:'#ffcc99',bodyFont:'monospace',headingFont:'monospace',radius:'12px',gap:'24px',scheme:'dark'};
function fixture(selection='default') {
 const listeners={},values={},style={setProperty:(k,v)=>values[k]=v,removeProperty:k=>delete values[k]};
 const parent={},window={parent,addEventListener:(event,fn)=>listeners[event]=fn};
 const ctx={window,parent,document:{documentElement:{dataset:{styleSelection:selection},style},body:{style}}};
 vm.createContext(ctx);vm.runInContext(fs.readFileSync('clusterctl/homes/assets/artifact-style.js','utf8'),ctx);
 return {listeners,values,parent};
}
test('actual parent sends validated appearance; siblings/null origin/unsafe CSS never alter style',()=>{
 const f=fixture();const data={type:'home-artifact:style',contract:'homemaker.appearance/v1',appearance};
 for(const event of [{source:{},origin:'https://home.example',data},{source:f.parent,origin:'null',data},{source:f.parent,origin:'https://home.example',data:{...data,appearance:{...appearance,bodyFont:'url(https://hostile)'}}}])f.listeners.message(event);
 assert.deepEqual(f.values,{});
 f.listeners.message({source:f.parent,origin:'https://home.example',data});assert.equal(f.values['--space'],appearance.background);assert.equal(f.values['--home-font'],'monospace');
 f.listeners.message({source:f.parent,origin:'https://home.example',data:{...data,appearance:null}});assert.deepEqual(f.values,{});
});
test('explicitly authored work never subscribes to default appearance',()=>{assert.equal(fixture('explicit').listeners.message,undefined);});
