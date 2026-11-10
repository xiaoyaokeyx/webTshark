import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { build } from 'esbuild';
import { JSDOM } from 'jsdom';

test('VoIP requests only SIP, pages sessions, preserves cross-page selection and bounds grouped charts', async () => {
  const dir = await mkdtemp(join(process.cwd(), 'node_modules/.sip-workspace-test-'));
  const dom = new JSDOM('<div id="root"></div>', {url:'http://localhost', pretendToBeVisual:true});
  const previous = Object.fromEntries(['window','document','navigator','IS_REACT_ACT_ENVIRONMENT','fetch'].map(key => [key,Object.getOwnPropertyDescriptor(globalThis,key)]));
  let root;
  try {
    await build({entryPoints:['src/SipFlow.jsx'],bundle:true,platform:'node',format:'esm',packages:'external',outfile:join(dir,'sip.mjs'),logLevel:'silent'});
    for (const key of ['window','document','navigator']) Object.defineProperty(globalThis,key,{value:dom.window[key],configurable:true,writable:true});
    globalThis.IS_REACT_ACT_ENVIRONMENT = true;
    const packets = Array.from({length:60}, (_,i) => ({no:i+1,time:i,epoch:1700000000+i,protocol:'SIP',source:'192.0.2.1',destination:'198.51.100.1',info:'INVITE sip:b',fields:{'sip.Call-ID':`call-${i+1}`,'sip.CSeq.method':'INVITE'}}));
    const requests=[];
    globalThis.fetch = async (url) => {
      requests.push(new URL(url,'http://localhost'));
      return {ok:true,json:async()=>({packets,total:packets.length,pageSize:500})};
    };
    const React = await import('react');
    const {createRoot} = await import('react-dom/client');
    const {default:SipFlow} = await import(pathToFileURL(join(dir,'sip.mjs')));
    root=createRoot(document.getElementById('root'));
    const render = (id='capture') => root.render(React.createElement(SipFlow,{capture:{id,revision:1},filter:'sip_mrcp.port=20000 || tcp',timeFormat:'relative',formatTime:p=>String(p.time)}));
    await React.act(async()=>render());
    assert.equal(requests[0].searchParams.get('filter'),'(sip_mrcp.port=20000 || tcp) && sip');
    assert.equal(document.querySelectorAll('.voip-call-table tbody tr').length,50);
    const byLabel = label => document.querySelector(`[aria-label="${label}"]`);
    const click = async el => React.act(()=>el.dispatchEvent(new dom.window.MouseEvent('click',{bubbles:true})));
    const select = async (el,value) => React.act(()=>{el.value=value;el.dispatchEvent(new dom.window.Event('change',{bubbles:true}));});
    await click(byLabel('显示会话 1'));
    assert.equal(byLabel('显示全部匹配会话').indeterminate,true);
    await click(byLabel('下一页会话'));
    assert.equal(document.querySelectorAll('.voip-call-table tbody tr').length,10);
    await click(byLabel('上一页会话'));
    assert.equal(byLabel('显示会话 1').checked,false);
    await select(byLabel('会话排序'),'newest');
    assert.match(document.querySelector('.voip-call-table tbody tr').textContent,/会话 60/);
    await select(byLabel('会话排序'),'start');
    await click(byLabel('显示全部匹配会话'));
    const chartButton = [...document.querySelectorAll('button')].find(b=>b.textContent==='时序图');
    await click(chartButton);
    await click([...document.querySelectorAll('button')].find(b=>b.textContent==='按会话分组'));
    assert.equal(document.querySelectorAll('.voip-chart').length,10);
    await click(byLabel('下一组时序图'));
    assert.equal(document.querySelector('.voip-chart').getAttribute('aria-label'),'会话 11 时序图');
    await React.act(async()=>render('other-capture'));
    assert.equal(document.querySelectorAll('.voip-chart').length,0);
    assert.equal(byLabel('上一页会话').disabled,true);
    assert.equal(byLabel('显示全部匹配会话').checked,true);
  } finally {
    if(root) { const {act}=await import('react'); await act(()=>root.unmount()); }
    dom.window.close();
    for(const [key,descriptor] of Object.entries(previous)) {
      if(descriptor) Object.defineProperty(globalThis,key,descriptor); else delete globalThis[key];
    }
    await rm(dir,{recursive:true,force:true});
  }
});
