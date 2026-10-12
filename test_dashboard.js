// Exercise the real dashboard handlers across a transient status disconnection.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const html = fs.readFileSync(__dirname + '/dashboard.html', 'utf8');
const nodes = new Map();
function element(id = '') {
  return {id, disabled:false, value:'', dataset:{}, children:[],
    replaceChildren(){this.children=[]}, append(child){this.children.push(child)}};
}
const get = id => {if(!nodes.has(id))nodes.set(id,element(id));return nodes.get(id)};
const routeIDs = ['profile-select','policy-select','prefer-select'];
const formIDs = ['link-method','link-direction','spoof-up','spoof-down'];
for(const id of formIDs)get(id).value='user-choice-'+id;
const routeButton = element('route-button');
const context = vm.createContext({$:get, text:(id,value)=>{get(id).textContent=value},t:x=>x,
 controlToken:'fixture-token',frozen:null,document:{activeElement:null,
 createElement:()=>element(), querySelectorAll(selector){
   return selector.split(',').flatMap(s => s==='.controlgrid select'
     ? [...routeIDs,...formIDs].map(get) : s==='.rowbuttons button' ? [routeButton]
     : s.startsWith('#') ? [get(s.slice(1))] : []);
 }}});
for(const name of ['selectOptions','controls','showDisconnected']){
 const line=html.split('\n').find(line=>line.startsWith('function '+name+'('));
 assert.ok(line, 'missing dashboard handler '+name);vm.runInContext(line,context);
}
const status={routes:[{name:'healthy',enabled:true,state:'UP'}],profiles:{All:['healthy']},profile:'All',policy:'priority',preferred:null};
context.status=status;
for(let i=0;i<3;i++){
 vm.runInContext('controls(status);showDisconnected()',context);
 for(const id of routeIDs)assert.equal(get(id).disabled,true,id+' must stop controlling stale routes');
 assert.equal(routeButton.disabled,true);
 for(const id of formIDs){assert.equal(get(id).disabled,false,id+' must remain editable');assert.equal(get(id).value,'user-choice-'+id)}
 vm.runInContext('controls(status)',context);
 for(const id of routeIDs)assert.equal(get(id).disabled,false,id+' must recover');
}
context.controlToken=null;vm.runInContext('controls(status)',context);
for(const id of routeIDs)assert.equal(get(id).disabled,true,'read-only controls remain disabled');
console.log('Dashboard transient-disconnection regression passed');
