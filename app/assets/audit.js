/* Readable audit activity. Stored records and destructive-action controls remain server-owned. */
let AUDIT_ENTRIES=[],AUDIT_PAGE=0,AUDIT_LOAD_ERROR='';
const AUDIT_PAGE_SIZE=25;
const auditEscape=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function auditParse(value,depth=0){
 if(depth>8)return value;
 if(typeof value==='string'){
  const text=value.trim();
  if((text.startsWith('{')&&text.endsWith('}'))||(text.startsWith('[')&&text.endsWith(']'))){try{return auditParse(JSON.parse(text),depth+1)}catch(_){}}
  return value;
 }
 if(Array.isArray(value))return value.map(v=>auditParse(v,depth+1));
 if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value).map(([k,v])=>[k,auditParse(v,depth+1)]));
 return value;
}
function auditLabel(value){
 const known={login_success:'Successful sign-in',login_failed:'Failed sign-in',login_failure:'Failed sign-in',logout:'Signed out',windows_agent_command_completed:'Windows agent action completed',windows_agent_command_failed:'Windows agent action failed',edr_defender_quick:'Defender quick scan requested',edr_defender_review:'Defender status requested',edr_defender_update:'Defender signature update requested',edr_defender_remediate:'Defender threat removal requested',audit_log_cleared:'Audit log cleared',ok:'Result',agent_id:'Agent ID',command_type:'Action',new_findings:'New findings',RealTimeProtectionEnabled:'Real-time protection',AntivirusEnabled:'Antivirus enabled',AMRunningMode:'Protection mode',SignatureLastUpdated:'Signatures updated',QuickScanEndTime:'Quick scan finished',RecentDetections:'Recent detections',ThreatID:'Threat ID',ActionSuccess:'Action succeeded',InitialDetectionTime:'First detected',Resources:'Affected resources'};
 if(known[value])return known[value];
 return String(value||'Activity').replace(/([a-z0-9])([A-Z])/g,'$1 $2').replace(/[_-]+/g,' ').replace(/^./,c=>c.toUpperCase()).replace(/\b(ip|id|mfa|edr|yara|tls|crm|kb)\b/gi,v=>v.toUpperCase());
}
function auditCategory(row){const a=String(row.action||'');if(/login|logout|mfa|session|password|auth/.test(a))return 'access';if(/windows_agent|edr_|defender|clamav|remote_/.test(a))return 'endpoint';if(/user|role|permission|backup|restore|config|cleared|delete|cleanup|settings/.test(a))return 'administration';return 'other'}
function auditOutcome(row){const d=row.parsed;if(d?.ok===false||/failed|failure|denied|error/.test(row.action||''))return {label:'Failed',kind:'bad'};if(d?.ok===true||row.action==='login_success')return {label:'Succeeded',kind:'good'};if(row.action==='logout')return {label:'Signed out',kind:'neutral'};if(/edr_defender_|requested|queued/.test(row.action||''))return {label:'Requested',kind:'pending'};return {label:'Recorded',kind:'neutral'}}
function auditDate(value){
 if(value===null||value===undefined||value==='')return 'Not recorded';
 const dotnet=typeof value==='string'&&value.match(/^\/Date\((-?\d+)(?:[+-]\d{4})?\)\/$/);
 const date=new Date(dotnet?Number(dotnet[1]):value);return Number.isNaN(date.getTime())?String(value??'—'):date.toLocaleString();
}
function auditValue(value,key=''){
 if(value===null||value===undefined||value==='')return '<span class="audit-muted">Not recorded</span>';
 if(typeof value==='boolean')return `<span class="audit-value-badge ${value?'yes':'no'}">${value?'Yes':'No'}</span>`;
 if(typeof value==='string'&&(/^\/Date\(/.test(value)||(/time|updated|_at|date/i.test(key)&&/^\d{4}-\d{2}-\d{2}T/.test(value))))return auditEscape(auditDate(value));
 if(typeof value==='string'&&key==='command_type')return auditEscape(auditLabel(value));
 return auditEscape(value);
}
function auditFields(value,depth=0){
 if(depth>6)return '<details class="audit-nested"><summary>More details</summary><pre>'+auditEscape(JSON.stringify(value,null,2))+'</pre></details>';
 if(Array.isArray(value)){
  if(!value.length)return '<div class="audit-empty-field">No items reported</div>';
  const render=v=>`<div class="audit-array-item">${auditFields(v,depth+1)}</div>`;
  return `<div class="audit-array">${value.slice(0,12).map(render).join('')}</div>`+(value.length>12?`<details class="audit-nested"><summary>Show ${value.length-12} more items</summary><div class="audit-array">${value.slice(12).map(render).join('')}</div></details>`:'');
 }
 if(value&&typeof value==='object'){
  const entries=Object.entries(value);if(!entries.length)return '<div class="audit-empty-field">No additional fields</div>';
  const scalar=entries.filter(([,v])=>!v||typeof v!=='object'),nested=entries.filter(([,v])=>v&&typeof v==='object');
  return (scalar.length?'<dl class="audit-fields">'+scalar.map(([k,v])=>`<div><dt>${auditEscape(auditLabel(k))}</dt><dd>${auditValue(v,k)}</dd></div>`).join('')+'</dl>':'')+nested.map(([k,v])=>`<section class="audit-detail-section"><h4>${auditEscape(auditLabel(k))}${Array.isArray(v)?' <span>'+v.length+'</span>':''}</h4>${auditFields(v,depth+1)}</section>`).join('');
 }
 return `<div class="audit-text-detail">${auditValue(value)}</div>`;
}
function auditIcon(category){const paths={access:'M12 3 20 6v6c0 5-8 9-8 9s-8-4-8-9V6Z M8 12l3 3 5-6',endpoint:'M3 4h18v13H3Z M8 21h8 M12 17v4',administration:'M4 6h16 M4 12h16 M4 18h16 M8 3v6 M16 9v6 M10 15v6',other:'M6 3h9l4 4v14H6Z M14 3v5h5 M9 12h7 M9 16h7'};return `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="${paths[category]||paths.other}"/></svg>`}
function auditSummary(row){
 const d=row.parsed;
 if(d&&typeof d==='object'&&!Array.isArray(d)){
  const parts=[];if(d.command_type)parts.push(auditLabel(d.command_type));if(d.agent_id!=null)parts.push('Agent '+d.agent_id);if(d.events!=null)parts.push(d.events+' events');if(d.new_findings!=null)parts.push(d.new_findings+' new findings');
  const detections=d.details?.RecentDetections;if(detections)parts.push((Array.isArray(detections)?detections.length:1)+' recent detections');
  if(parts.length)return parts.join(' · ');
  if(d.reason)return String(d.reason);
  return Object.keys(d).length+' recorded field'+(Object.keys(d).length===1?'':'s');
 }
 if(/^edr_defender_/.test(row.action||'')&&/^\d+$/.test(String(d)))return 'Command #'+d+' queued for the Windows agent';
 return String(d||'Open for recorded details').slice(0,180);
}
function auditSetFilter(value){document.getElementById('auditCategory').value=value;AUDIT_PAGE=0;renderAudit()}
function auditResetFilters(){document.getElementById('auditSearch').value='';document.getElementById('auditCategory').value='all';document.getElementById('auditPeriod').value='all';AUDIT_PAGE=0;renderAudit()}
function auditPage(delta){AUDIT_PAGE=Math.max(0,AUDIT_PAGE+delta);renderAudit();document.getElementById('auditResults')?.focus()}
function renderAudit(){
 const category=document.getElementById('auditCategory').value,q=document.getElementById('auditSearch').value.trim().toLowerCase(),period=Number(document.getElementById('auditPeriod').value)||0,cutoff=Date.now()-period*86400000;
 const rows=AUDIT_ENTRIES.filter(r=>(category==='all'||r.category===category||category==='review'&&r.outcome.kind==='bad')&&(!q||r.search.includes(q))&&(!period||Date.parse(r.created_at)>=cutoff));
 const pages=Math.max(1,Math.ceil(rows.length/AUDIT_PAGE_SIZE));AUDIT_PAGE=Math.min(AUDIT_PAGE,pages-1);
 const counts={all:AUDIT_ENTRIES.length,access:AUDIT_ENTRIES.filter(r=>r.category==='access').length,endpoint:AUDIT_ENTRIES.filter(r=>r.category==='endpoint').length,review:AUDIT_ENTRIES.filter(r=>r.outcome.kind==='bad').length};
 for(const [key,count] of Object.entries(counts)){document.getElementById('auditCount-'+key).textContent=AUDIT_LOAD_ERROR?'—':count;const button=document.querySelector('[data-audit-filter="'+key+'"]');button?.setAttribute('aria-pressed',String(category===key))}
 document.getElementById('auditResultCount').textContent=`${rows.length} matching entries · showing ${rows.length?AUDIT_PAGE*AUDIT_PAGE_SIZE+1:0}–${Math.min(rows.length,(AUDIT_PAGE+1)*AUDIT_PAGE_SIZE)} of ${AUDIT_ENTRIES.length} loaded`;
 document.getElementById('auditPrev').disabled=AUDIT_PAGE===0;document.getElementById('auditNext').disabled=AUDIT_PAGE>=pages-1;document.getElementById('auditPageLabel').textContent='Page '+(AUDIT_PAGE+1)+' of '+pages;
 document.getElementById('auditResults').innerHTML=rows.length?rows.slice(AUDIT_PAGE*AUDIT_PAGE_SIZE,(AUDIT_PAGE+1)*AUDIT_PAGE_SIZE).map(row=>{
  const protectedNow=row.protected_until&&Date.parse(row.protected_until)>Date.now();
  return `<details class="audit-entry"><summary><span class="audit-action-icon ${row.category}">${auditIcon(row.category)}</span><div class="audit-entry-main"><div class="audit-entry-title"><h3>${auditEscape(auditLabel(row.action))}</h3><span class="audit-outcome ${row.outcome.kind}">${row.outcome.label}</span>${protectedNow?'<span class="audit-outcome protected">Protected record</span>':''}</div><p>${auditEscape(auditSummary(row))}</p><div class="audit-entry-meta"><span><b>User</b> ${auditEscape(row.actor||'Not recorded')}</span><span><b>Target</b> ${auditEscape(row.target||'Not recorded')}</span><span><b>IP</b> ${auditEscape(row.ip||'Not recorded')}</span></div></div><div class="audit-entry-time"><time>${auditEscape(auditDate(row.created_at))}</time><span>View details <i aria-hidden="true">⌄</i></span></div></summary><div class="audit-entry-body">${protectedNow?`<p class="audit-protection-note">Protected until ${auditEscape(auditDate(row.protected_until))}. The existing audit retention hold applies.</p>`:''}<h4>Recorded details</h4>${auditFields(row.parsed)}<details class="audit-raw"><summary>Original record · technical view</summary><dl class="audit-fields"><div><dt>Action code</dt><dd>${auditEscape(row.action)}</dd></div><div><dt>Entry ID</dt><dd>${auditEscape(row.id)}</dd></div></dl><pre>${auditEscape(typeof row.details==='string'?row.details:JSON.stringify(row.details??'',null,2))}</pre></details></div></details>`;
 }).join(''):'<div class="audit-empty">'+(AUDIT_LOAD_ERROR?'Audit activity is unavailable. Refresh to try again.':AUDIT_ENTRIES.length?'No activity matches these filters. Select Reset filters to see the loaded entries.':'No audit entries recorded yet.')+'</div>';
}
async function loadAudit(){
 const panel=document.getElementById('auditPanel');if(!panel||!ME)return;
 const access=ME.page_access?.audit,allowed=ME.role==='admin'||(access?access!=='none':['admin','auditor'].includes(ME.role));panel.hidden=!allowed;if(!allowed)return;
 const notice=document.getElementById('auditNotice');notice.textContent='Loading audit activity…';
 try{const rows=await json('/api/v1/audit?limit=500');AUDIT_LOAD_ERROR='';AUDIT_ENTRIES=(rows||[]).map(row=>{const parsed=auditParse(row.details),item={...row,parsed};return {...item,category:auditCategory(item),outcome:auditOutcome(item),search:[row.actor,row.action,auditLabel(row.action),row.target,row.ip,row.created_at,row.details].join(' ').toLowerCase()}});renderAudit();notice.textContent='Latest '+AUDIT_ENTRIES.length+' records loaded · summary counts refer to this loaded history.'}
 catch(e){AUDIT_LOAD_ERROR=e.message||'Request failed';AUDIT_ENTRIES=[];renderAudit();notice.textContent='Unable to load audit activity: '+AUDIT_LOAD_ERROR}
}
