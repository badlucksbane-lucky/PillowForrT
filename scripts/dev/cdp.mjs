// A tiny Chrome DevTools Protocol driver for the other scripts here (no dependencies; Node 22). connect() opens a new tab, or attaches to an existing one with connect({target})
// (Chrome on Android refuses new tabs, so attach there). CDP_PORT picks the debugging port (default 9222); screenshots go to $SHOTS (default the current directory).
import fs from 'node:fs';
const PORT=process.env.CDP_PORT||9222;
export async function connect(opts={}){
  const t=opts.target||await (await fetch(`http://127.0.0.1:${PORT}/json/new?about:blank`,{method:'PUT'})).json();
  const ws=new WebSocket(t.webSocketDebuggerUrl);await new Promise(r=>ws.onopen=r);
  let id=0;const pend=new Map(),ev=[];const logs=[];
  ws.onmessage=m=>{const d=JSON.parse(m.data);if(d.id&&pend.has(d.id)){const {res,rej}=pend.get(d.id);pend.delete(d.id);d.error?rej(new Error(JSON.stringify(d.error))):res(d.result)}else if(d.method){ev.push(d);
    if(d.method==='Runtime.exceptionThrown')logs.push('EXC '+(d.params.exceptionDetails.exception?.description||d.params.exceptionDetails.text));
    if(d.method==='Log.entryAdded')logs.push('LOG '+d.params.entry.level+' '+d.params.entry.text+' '+(d.params.entry.url||''));
    if(d.method==='Runtime.consoleAPICalled'&&['error','warning'].includes(d.params.type))logs.push('CON '+d.params.type+' '+d.params.args.map(a=>a.value||a.description).join(' '));}};
  const send=(method,params={})=>new Promise((res,rej)=>{const i=++id;pend.set(i,{res,rej});ws.send(JSON.stringify({id:i,method,params}))});
  await send('Page.enable');await send('Runtime.enable');await send('Log.enable');
  const api={send,logs,events:ev,
    async mobile(){await send('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:2,mobile:true});await send('Emulation.setTouchEmulationEnabled',{enabled:true})},
    async desktop(){await send('Emulation.setDeviceMetricsOverride',{width:1200,height:800,deviceScaleFactor:1,mobile:false})},
    async goto(url){await send('Page.navigate',{url})},
    async ev(expr){const r=await send('Runtime.evaluate',{expression:expr,returnByValue:true,awaitPromise:true});if(r.exceptionDetails)throw new Error(r.exceptionDetails.exception?.description||'eval failed');return r.result.value},
    async wait(ms){await new Promise(r=>setTimeout(r,ms))},
    async until(expr,ms=20000){const t0=Date.now();while(Date.now()-t0<ms){try{if(await api.ev(expr))return true}catch(e){}await api.wait(300)}return false},
    async shot(name){const r=await send('Page.captureScreenshot',{format:'png'});fs.writeFileSync(`${process.env.SHOTS||'.'}/${name}.png`,Buffer.from(r.data,'base64'))},
    async swipe(x0,y0,x1,y1,steps=8){const p=(type,x,y)=>send('Input.dispatchTouchEvent',{type,touchPoints:type==='touchEnd'?[]:[{x,y}]});await p('touchStart',x0,y0);for(let i=1;i<=steps;i++){await p('touchMove',x0+(x1-x0)*i/steps,y0+(y1-y0)*i/steps);await api.wait(16)}await p('touchEnd');},
    close(){ws.close();if(!opts.target)fetch(`http://127.0.0.1:${PORT}/json/close/${t.id}`).catch(()=>{})}};
  return api;
}
