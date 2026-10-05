"""Run real summary handlers/renderers against representative data, without an agent."""
import json
import re
import shutil
import subprocess
from pathlib import Path

SOURCE = Path('app/main.py').read_text()

def function(name):
    # End at the next top-level function/variable declaration, preserving the production body.
    start = SOURCE.index('function '+name+'(')
    start = start - 6 if SOURCE[max(0, start-6):start] == 'async ' else start
    end = re.search(r'\n(?:async function |function |let |const |window\.)', SOURCE[start+1:])
    return SOURCE[start:start+1+end.start()] if end else SOURCE[start:]

def test_summary_cards_are_native_buttons_with_real_targets():
    ids = ['edrProtected','edrAlerts','edrPending','edrPack','findingOpen','findingResolved',
           'findingAll','findingCritical','eventFindingOpen','eventFindingCritical',
           'eventFindingHardware','eventFindingResolved','ticketOpen','ticketInProgress',
           'ticketScheduled','ticketClosed','monitorTotalSummary','monitorHealthySummary',
           'monitorFailingSummary','monitorDisabledSummary','reportGeneratedCount',
           'reportScheduleCount','reportLatestType','trafficSourceLabel','traffic24Rx',
           'traffic24Tx','trafficDeviceCount']
    for id in ids:
        line = next(x for x in SOURCE.splitlines() if f'id="{id}"' in x)
        assert '<button type="button"' in line and 'summary-action' in line and 'onclick=' in line, id
    assert '.summary-action:focus-visible' in SOURCE

def test_summary_handlers_filter_live_data_and_keep_record_actions():
    assert shutil.which('node'), 'Node is needed to execute the production browser handlers'
    funcs = ['openSummaryFilter','openEdrSummary','renderEdrJobs','edrFresh','edrDetections',
             'edrTime','edrJobSummary','renderEdrEndpoints','loadTickets','loadFindings',
             'loadEventFindings','loadMonitoring']
    script = r'''
const assert=require('node:assert/strict');
const elements=new Map();
const element=id=>{if(!elements.has(id))elements.set(id,{value:'',hidden:true,textContent:'',innerHTML:'',classList:{},querySelector(){return element(id+'Label')}});return elements.get(id)};
global.document={getElementById:element,querySelectorAll:()=>[]};
for(const id of ['ticketStatusFilter','eventFindingStatusFilter','eventFindingSeverityFilter','eventFindingSearch','ticketOpen','ticketInProgress','ticketScheduled','ticketClosed','ticketRows','findingOpen','findingResolved','findingAll','findingCritical','findingRows','eventFindingOpen','eventFindingResolved','eventFindingCritical','eventFindingHardware','eventFindingRows','monitorRows'])global[id]=element(id);
let EDR_VIEW_DATA,EDR_ENDPOINT_FILTER='all',EDR_JOB_FILTER='all',TICKETS=[],MONITORS=[],EVENT_FINDINGS=[];
const SUMMARY_FILTERS={finding:'all',eventFinding:'all',ticket:'all',monitor:'all'};
const esc=x=>String(x??''),applyRoleVisibility=()=>{},updateTicketDeleteSelection=()=>{},updateEventFindingDeleteSelection=()=>{},loadWindowsAgents=async()=>{},loadWindowsSources=async()=>{},loadTicketAssignees=async()=>{},ticketAssigneeLabel=x=>x||'',showEdrTab=x=>global.tab=x;
const records={};async function json(url){if(!(url in records))throw Error('Unexpected API '+url);return records[url]}
'''+ '\n'.join(function(f) for f in funcs)+r'''
(async()=>{
 const fresh=new Date().toISOString();
 EDR_VIEW_DATA={agents:[{id:1,computer_name:'Protected PC',edr_enabled:true,edr_capable:true,defender_checked_at:fresh,defender:{RealTimeProtectionEnabled:true}},{id:2,computer_name:'Unprotected PC',edr_enabled:true,defender_checked_at:fresh,defender:{RealTimeProtectionEnabled:false}}],jobs:[{computer_name:'Queued PC',status:'pending'},{computer_name:'Delivered PC',status:'delivered'},{computer_name:'Finished PC',status:'completed'}]};
 openEdrSummary('protected');assert.equal(tab,'overview');assert(element('edrEndpoints').innerHTML.includes('Protected PC'));assert(!element('edrEndpoints').innerHTML.includes('Unprotected PC'));assert.equal(element('edrSummaryFilter').hidden,false);
 openEdrSummary('all');assert(element('edrEndpoints').innerHTML.includes('Unprotected PC'));
 openEdrSummary('alerts');assert.equal(tab,'alerts');openEdrSummary('rules');assert.equal(tab,'rules');
 openEdrSummary('pending');assert.equal(tab,'scans');assert(element('edrJobs').innerHTML.includes('Queued PC'));assert(element('edrJobs').innerHTML.includes('Delivered PC'));assert(!element('edrJobs').innerHTML.includes('Finished PC'));
 EDR_VIEW_DATA.jobs=[];renderEdrJobs();assert(element('edrJobs').innerHTML.includes('No pending actions'));
 records['/api/v1/tickets']=['open','assigned','waiting','in_progress','closed'].map((status,i)=>({id:i+1,status,title:'Ticket-'+status,priority:'medium',updated_at:fresh,calendar_event_id:status==='assigned'?1:null}));
 for(const [kind,expected] of [['open',3],['in_progress',1],['scheduled',1],['closed',1],['all',5]]){openSummaryFilter('ticket',kind);await loadTickets();assert.equal((ticketRows.innerHTML.match(/onclick="openTicketEditor/g)||[]).length,expected,kind)}
 records['/api/v1/intelligence/issues?status=open']=[{id:1,title:'Critical open',status:'open',severity:'critical'},{id:2,title:'Medium open',status:'open',severity:'medium'}];records['/api/v1/intelligence/issues?status=resolved']=[{id:3,title:'High resolved',status:'resolved',severity:'high'}];
 openSummaryFilter('finding','critical');await loadFindings();assert(findingRows.innerHTML.includes('High resolved'));assert(!findingRows.innerHTML.includes('Medium open'));assert.equal(findingCritical.textContent,2);
 openSummaryFilter('finding','all');await loadFindings();assert(findingRows.innerHTML.includes('Medium open'));assert.equal(element('findingSummaryFilter').hidden,true);
 records['/api/v1/monitoring/settings']=[{id:1,name:'Healthy monitor',enabled:true},{id:2,name:'Failed monitor',enabled:true},{id:3,name:'Disabled monitor',enabled:false}];records['/api/v1/monitoring/checks']=[{monitor_id:1,status:'up',last_checked:fresh},{monitor_id:2,status:'down',last_checked:fresh}];
 for(const [kind,name] of [['healthy','Healthy monitor'],['attention','Failed monitor'],['disabled','Disabled monitor']]){openSummaryFilter('monitor',kind);await loadMonitoring();assert(monitorRows.innerHTML.includes(name));assert.equal((monitorRows.innerHTML.match(/<tr>/g)||[]).length,1)}
 const events=[{id:1,title:'Disk failure',category:'Storage',severity:'critical'},{id:2,title:'Software failure',category:'Application',severity:'medium'}];records['/api/v1/event-findings?status=open']=events;records['/api/v1/event-findings?status=resolved']=[];records['/api/v1/event-findings?status=open&severity=&q=']=events;
 openSummaryFilter('eventFinding','hardware');await loadEventFindings();assert(eventFindingRows.innerHTML.includes('Disk failure'));assert(!eventFindingRows.innerHTML.includes('Software failure'));
 console.log('PASS: EDR drilldowns, pending/empty states, ticket groups, finding severity, monitor groups, storage events, and reset controls');
})().catch(e=>{console.error(e);process.exit(1)});
'''
    result = subprocess.run(['node','-e',script], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_map_motion_has_pause_and_reduced_motion_support():
    assert 'map-hop-flow 5s linear infinite' in SOURCE
    assert 'animation-play-state:paused' in SOURCE
    assert '@media(prefers-reduced-motion:reduce){.map-hop-motion,.map-motion-toggle{display:none}}' in SOURCE
    assert 'function toggleMapMotion(button)' in SOURCE
    assert "button.setAttribute('aria-pressed',String(paused))" in SOURCE
