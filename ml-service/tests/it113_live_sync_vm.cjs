const vm = require('vm');
const fs=require('fs');
const assert=require('assert');
const path=require('path');
const base=path.resolve(__dirname,'../../public/assessment')+path.sep;
const script=fs.readFileSync(base+'it113-live.js','utf8');
const evidence=JSON.parse(fs.readFileSync(base+'evidence.json','utf8'));
const metadata=JSON.parse(fs.readFileSync(base+'model_summary.json','utf8'));
const labelById=Object.fromEntries(evidence.examples.map(x=>[x.id,x.true_label]));
const makeRow=(id,sample,label)=>({trace_id:String(id).padStart(32,'0'),at:new Date().toISOString(),source_type:'curated',sample_id:sample,expected_label:label,classification:label,confidence:.98,anomaly_score:.9,rule_score:53,risk_score:78,severity:'HIGH',model_version:'a'.repeat(16),indicator_evidence:[{description:'Failures over time',observed:40}],status:'OPEN',revision:0,synthetic:true,database_written:true,public_read_only:true});
const feed=[makeRow(1,'brute_force_correct','BRUTE_FORCE')];
let seq=1;
function newBrowser(oldStorage){
 const store=oldStorage||new Map(),elements=new Map(),listeners={},intervals=[];
 function element(id){if(!elements.has(id))elements.set(id,{id,innerHTML:'',textContent:'',dataset:{},disabled:false,hidden:false,value:id==='live-sample-select'?'brute_force_correct':'',addEventListener(event,fn){listeners[id+':'+event]=fn},dispatchEvent(ev){listeners[id+':'+ev.type]?.()},classList:{toggle(){}}});return elements.get(id)}
 const doc={getElementById:element,querySelectorAll(){return []},addEventListener(event,fn){listeners['document:'+event]=fn},hidden:false};
 function response(data,status=200){return {ok:status===200,status,json:async()=>JSON.parse(JSON.stringify(data))};}
 async function fetch(url,opts={}){
  if(url.startsWith('/assessment/evidence.json'))return response(evidence);
  if(url.startsWith('/assessment/model_summary.json'))return response(metadata);
  if(url==='/it113_public_project.php')return response({ok:true,read_only:true,enabled:true,entries:feed});
  if(url.startsWith('/it113_demo_history.php'))return response({ok:true,enabled:true,entries:[],storage_state:'ready'});
  if(url==='/it113_demo_infer.php'){
   let body=JSON.parse(opts.body),id=body.sample_id||'NUMERIC_CSV',label=labelById[id]||'NORMAL';
   let row=makeRow(++seq,id,label);
   if(!body.sample_id)row={...row,source_type:'numeric_csv',expected_label:null,public_read_only:false};
   else feed.unshift(row);
   return response({...row,ok:true,mode:body.sample_id?'live_inference_on_curated_synthetic_sample':'live_inference_on_numeric_security_features'});
  }
  throw Error('Unknown fetch '+url);
 }
 const storage={getItem:key=>store.has(key)?store.get(key):null,setItem:(key,v)=>store.set(key,v),removeItem:(key)=>store.delete(key)};
 const window={addEventListener(event,fn){listeners['window:'+event]=fn},confirm:()=>true};
 const context={document:doc,window,localStorage:storage,fetch,AbortController,Date,Event:class{constructor(type){this.type=type}},setTimeout,clearTimeout,setInterval:(fn,ms)=>{intervals.push([fn,ms]);return 1},console};
 vm.runInNewContext(script,context,{filename:'it113-live.js'});
 return {elements,element,store,intervals,listeners};
}
async function settle(){await new Promise(r=>setTimeout(r,35));}
(async()=>{
 const one=newBrowser(),two=newBrowser();await settle();
 assert(one.element('live-result').innerHTML.includes('Brute Force'));
 assert(two.element('live-result').innerHTML.includes('Brute Force'));
 assert.equal(one.intervals[0][1],20000);
 one.element('live-sample-select').value='normal_correct';
 await one.listeners['live-run-button:click']();await settle();
 assert(one.element('live-result').innerHTML.includes('Normal'));
 await two.intervals[0][0]();await settle();
 assert(two.element('live-result').innerHTML.includes('Normal'));
 const reload=newBrowser(two.store);await settle();
 assert(reload.element('live-result').innerHTML.includes('Normal'));
 assert(reload.element('live-sync-note').textContent.includes('Shared public analysis'));
 // A malicious numeric entry in the public response is never displayed or cached.
 const latest=feed.shift();feed.unshift({...makeRow(999,'NUMERIC_CSV','WEB_ATTACK'),source_type:'numeric_csv',public_read_only:false});
 await two.intervals[0][0]();await settle();
 assert(!two.element('live-result').innerHTML.includes('Web Attack'));
 feed.shift();feed.unshift(latest);
 console.log('PASS: two distinct clients, automatic shared update, refresh persistence, private data excluded, 20 s interval');
})().catch(err=>{console.error(err);process.exit(1)});
