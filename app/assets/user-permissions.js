/* GODSEYE Users & Permissions — scoped account workspace.
 * Uses existing admin-authenticated APIs; no agent dependencies. */
(function(){
'use strict';
let users=[], selectedId=null, selected=null, draft=null, saved=null, generation=0;
const el=id=>document.getElementById(id);
const nameFor=x=>x.display_name||x.username;
const roleName=role=>role==='readonly'?'Read-Only':role?role[0].toUpperCase()+role.slice(1):'';
const safe=x=>typeof esc==='function'?esc(String(x??'')):String(x??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const initials=x=>nameFor(x).trim().split(/\s+/).slice(0,2).map(t=>t[0]||'').join('').toUpperCase();
const status=(msg,bad)=>{if(el('upSaveStatus')){el('upSaveStatus').textContent=msg;el('upSaveStatus').classList.toggle('up-error',!!bad)}};
function filterUserCards(){
 const q=(el('upSearch')?.value||'').toLowerCase().trim(),root=el('usersCards');if(!root)return;
 const matches=users.filter(x=>[x.username,x.display_name,x.role].some(v=>String(v||'').toLowerCase().includes(q)));
 root.innerHTML=matches.length?matches.map(x=>'<button type="button" class="up-account '+(x.id===selectedId?'selected':'')+'" onclick="selectPermissionUser('+Number(x.id)+')" aria-pressed="'+(x.id===selectedId)+'"><span class="up-avatar">'+safe(initials(x))+'</span><span class="up-account-detail"><strong>'+safe(nameFor(x))+'</strong><small>'+safe(x.username)+' · '+safe(roleName(x.role))+'</small></span><span class="up-account-role">'+safe(roleName(x.role))+'</span></button>').join(''):'<p class="muted">No matching users.</p>';
}
function renderNewUserPreview(){
 const role=el('newUserRole')?.value,checked=el('upUseRoleDefaults')?.checked;
 if(el('upCreateRightsHint'))el('upCreateRightsHint').textContent=checked?'Inherit '+roleName(role)+' defaults. Select the account card later to customize individual rights.':'After creating the user, select their account card to customize individual rights before sharing credentials.';
}
async function renderUserManagement(){
 if(!el('usersPanel')||typeof ME==='undefined'||!ME||ME.role!=='admin')return;
 const token=++generation;
 try{
  users=await json('/api/v1/users');
  if(token!==generation)return;
  if(typeof loadRoleAccess==='function')await loadRoleAccess();
  for(const [id,value] of [['upTotal',users.length],['upAdmins',users.filter(x=>x.role==='admin').length],['upOperators',users.filter(x=>x.role==='operator').length],['upAuditors',users.filter(x=>x.role==='auditor').length]])if(el(id))el(id).textContent=value;
  if(!users.some(x=>x.id===selectedId))selectedId=users[0]?.id??null;
  filterUserCards();
  if(selectedId!==null)await selectPermissionUser(selectedId);
  else if(el('upSelectedHeader'))el('upSelectedHeader').textContent='No user accounts yet.';
  renderNewUserPreview();
 }catch(e){if(el('usersCards'))el('usersCards').textContent='Unable to load users: '+e.message;status('Could not load account details',true)}
}
async function selectPermissionUser(id){
 if(draft&&saved&&JSON.stringify(draft)!==JSON.stringify(saved)&&!confirm('Discard unsaved permission changes?'))return;
 const token=++generation;
 selectedId=Number(id);selected=users.find(u=>u.id===selectedId)||null;
 filterUserCards();
 try{
  const data=await json('/api/v1/users/'+selectedId+'/access');
  if(token!==generation)return;
  selected=data;draft={...data.pages};saved={...data.pages};renderSelectedUser();status('');
 }catch(e){status('Could not load selected account: '+e.message,true)}
}
function renderSelectedUser(){
 if(!selected)return;
 const user={...(users.find(u=>u.id===selectedId)||{}),...selected.user},admin=user.role==='admin',self=user.username===ME.username;
 if(el('upSelectedHeader'))el('upSelectedHeader').innerHTML='<span class="up-avatar up-big">'+safe(initials(user))+'</span><div><strong>'+safe(nameFor(user))+'</strong><span class="up-role-pill">'+safe(roleName(user.role))+'</span><small>@'+safe(user.username)+(admin?' · Admin access is locked':' · Individual settings')+'</small></div>';
 const pages=selected.groups,labels=selected.labels;
 let rows='<div class="up-permission-heading"><span>Module / Feature</span><span>Full</span><span>Read-Only</span><span>No Access</span></div>';
 for(const [group,keys] of Object.entries(pages)){
  rows+='<div class="up-group-label">'+safe(group)+'</div>';
  for(const page of keys){
   rows+='<div class="up-permission-row"><strong>'+safe(labels[page]||page)+'</strong>';
   for(const level of ['full','read','none']){
    const checked=draft[page]===level?'checked':'';
    rows+='<label><input type="radio" name="up-'+safe(page)+'" value="'+level+'" '+checked+' '+(admin?'disabled':'')+' onchange="setPermissionLevel(\''+safe(page)+'\',\''+level+'\')" aria-label="'+safe(labels[page])+': '+(level==='read'?'Read-Only':level==='none'?'No Access':'Full')+'"></label>';
   } rows+='</div>';
  }
 }
 if(el('upPermissionRows'))el('upPermissionRows').innerHTML=rows;
 if(el('upSave'))el('upSave').disabled=admin;
 const reset=el('upSave')?.previousElementSibling;if(reset)reset.disabled=admin;
 if(el('upAccountActions'))el('upAccountActions').innerHTML='<div class="up-account-info"><span>Last login: '+(user.last_login_at?safe(new Date(user.last_login_at).toLocaleString()):'Never')+'</span></div><label>Role <select class="filter" aria-label="Role for selected account" id="upRoleChange" '+(self?'disabled':'')+' onchange="changeSelectedUserRole(this.value)">'+['admin','operator','auditor','readonly'].map(role=>'<option value="'+role+'" '+(user.role===role?'selected':'')+'>'+roleName(role)+'</option>').join('')+'</select></label>'+(self?'':'<button type="button" class="secondary" onclick="resetSelectedUserPassword()">Reset password</button><button type="button" class="danger" onclick="removeSelectedUser()">Remove user</button>');
}
function setPermissionLevel(page,level){if(!draft||selected?.user.role==='admin')return;draft[page]=level;status('Unsaved changes')}
async function saveSelectedPermissions(){
 if(!selected||selected.user.role==='admin')return;
 try{
  await json('/api/v1/users/'+selectedId+'/access',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({pages:draft})});
  saved={...draft};status('Permissions saved. Existing sessions for this user have been revoked.');
  const data=await json('/api/v1/users/'+selectedId+'/access');selected=data;draft={...data.pages};saved={...data.pages};renderSelectedUser();
 }catch(e){status('Could not save permissions: '+e.message,true)}
}
async function resetSelectedPermissions(){
 if(!selected||selected.user.role==='admin')return;
 if(!confirm('Reset this account to inherited role defaults?'))return;
 try{
  await json('/api/v1/users/'+selectedId+'/access',{method:'DELETE'});
  const data=await json('/api/v1/users/'+selectedId+'/access');selected=data;draft={...data.pages};saved={...data.pages};renderSelectedUser();status('Restored role defaults; user sessions revoked.');
 }catch(e){status('Could not reset permissions: '+e.message,true)}
}
async function changeSelectedUserRole(role){
 if(!selected||selected.user.username===ME.username)return;
 await changeUserRole(selectedId,role);
}
function resetSelectedUserPassword(){
 if(!selected||selected.user.username===ME.username)return;
 const btn=document.createElement('button');btn.dataset.userId=selectedId;btn.dataset.username=selected.user.username;
 openUserPasswordReset(selectedId,btn);
}
function removeSelectedUser(){if(selected&&selected.user.username!==ME.username)removeUser(selectedId,selected.user.username)}
Object.assign(window,{renderUserManagement,filterUserCards,renderNewUserPreview,selectPermissionUser,setPermissionLevel,saveSelectedPermissions,resetSelectedPermissions,changeSelectedUserRole,resetSelectedUserPassword,removeSelectedUser});
})();
