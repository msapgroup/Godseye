"""Audit presentation preserves stored evidence while making nested agent results readable."""
from pathlib import Path
import subprocess
import shutil


def test_audit_gui_runtime():
    assert shutil.which('node'), 'Node is required to execute the real audit renderer'
    source=Path('app/assets/audit.js').read_text()
    harness=r'''
const assert=require('node:assert/strict');
const elements=new Map();function el(id){if(!elements.has(id))elements.set(id,{value:'',hidden:false,textContent:'',innerHTML:'',disabled:false,focus(){this.focused=true},setAttribute(k,v){this[k]=v}});return elements.get(id)}
global.document={getElementById:el,querySelector:()=>el('selected')};
let ME={role:'admin'},apiRows=[],apiCalls=0,apiFailure=false;async function json(url){assert.equal(url,'/api/v1/audit?limit=500');apiCalls++;if(apiFailure)throw new Error('Demo API unavailable');return apiRows}
el('auditCategory').value='all';el('auditPeriod').value='all';
'''+source+r'''
(async()=>{
 const fresh=new Date().toISOString(),nested=JSON.stringify({agent_id:2,command_type:'defender_review',ok:true,events:0,new_findings:0,details:JSON.stringify({AntivirusEnabled:true,RealTimeProtectionEnabled:true,AMRunningMode:'Normal',SignatureLastUpdated:'/Date(1791200000000)/',RecentDetections:[{ThreatID:170001,ActionSuccess:true,Resources:['file:C:\\Demo\\sample.exe']}]})});
 apiRows=[{id:1,action:'windows_agent_command_completed',actor:'windows-agent',details:nested,created_at:fresh,target:'650',ip:'192.0.2.10'},{id:2,action:'login_failed',actor:'demo',details:'Denied',created_at:fresh},{id:3,action:'audit_log_cleared',actor:'admin',details:'reason=test; deleted=4',created_at:fresh,protected_until:new Date(Date.now()+86400000).toISOString()},{id:4,action:'edr_defender_quick',details:'651',created_at:fresh},{id:5,action:'custom_action',actor:'<img src=x onerror=evil()>',details:JSON.stringify({note:'<script>evil()</script>'}),created_at:fresh}];
 await loadAudit();
 let html=el('auditResults').innerHTML;
 for(const label of ['Real-time protection','Recent detections','Threat ID','Affected resources','Original record','Protected record','Command #651'])assert(html.includes(label),label);
 assert(!html.includes('<script>evil()'));assert(html.includes('&lt;script&gt;evil()'));
 assert.equal(auditParse(nested).details.RealTimeProtectionEnabled,true);
 assert.equal(auditDate(null),'Not recorded');assert(!auditDate('/Date(1791200000000)/').includes('/Date'));
 assert.equal(auditOutcome({action:'windows_agent_command_completed',parsed:{ok:true}}).label,'Succeeded');
 assert.equal(auditOutcome({action:'windows_agent_command_completed',parsed:{ok:false}}).kind,'bad');
 assert.equal(el('auditCount-all').textContent,5);assert.equal(el('auditCount-review').textContent,1);
 auditSetFilter('review');assert(el('auditResults').innerHTML.includes('Failed sign-in'));assert(!el('auditResults').innerHTML.includes('Command #651'));
 auditResetFilters();el('auditSearch').value='defender_review';renderAudit();assert.equal((el('auditResults').innerHTML.match(/class="audit-entry"/g)||[]).length,1);
 el('auditSearch').value='NoSuchEntry';renderAudit();assert(el('auditResults').innerHTML.includes('No activity matches'));
 auditResetFilters();apiRows=Array.from({length:31},(_,i)=>({id:i,action:'login_success',actor:'demo-'+i,details:'',created_at:fresh}));await loadAudit();assert.equal((el('auditResults').innerHTML.match(/class="audit-entry"/g)||[]).length,25);auditPage(1);assert.equal((el('auditResults').innerHTML.match(/class="audit-entry"/g)||[]).length,6);assert.equal(el('auditNext').disabled,true);
 ME={role:'operator',page_access:{audit:'read'}};await loadAudit();assert.equal(el('auditPanel').hidden,false);
 apiFailure=true;await loadAudit();assert.equal(el('auditCount-all').textContent,'—');assert(el('auditResults').innerHTML.includes('Audit activity is unavailable'));apiFailure=false;
 const calls=apiCalls;ME={role:'auditor',page_access:{audit:'none'}};await loadAudit();assert.equal(el('auditPanel').hidden,true);assert.equal(apiCalls,calls);
 console.log('PASS: nested Defender JSON, dates, booleans, resource cards, escaped original evidence, outcome classification, filters, reset, paging, and configured audit access');
})().catch(e=>{console.error(e);process.exit(1)});
'''
    result=subprocess.run(['node','-e',harness],capture_output=True,text=True)
    assert result.returncode==0,result.stdout+result.stderr


def test_audit_assets_and_existing_clear_controls_remain_available():
    from fastapi.testclient import TestClient
    import app.main as main
    with TestClient(main.app) as client:
        for path in ['/assets/audit.js','/assets/audit.css']:
            response=client.get(path)
            assert response.status_code==200
    source=Path('app/main.py').read_text()
    assert 'class="danger admin-only" id="clearAuditBtn" onclick="openClearData(\'audit\')"' in source
    assert "user=Depends(require_admin)" in source[source.index('def clear_audit_log'):source.index('def clear_audit_log')+150]
    assert "protected_until=(stamp+dt.timedelta(days=7)).isoformat()" in source
