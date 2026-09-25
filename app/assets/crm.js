let CRM_ACTIVE_ID=null,CRM_SITES=[],CRM_CONTACT_EDIT=null,CRM_SEARCH_TIMER=null;
const crmApi=(path,method='GET',data)=>json('/api/v1/crm'+path,{method,headers:data===undefined?{}:{'Content-Type':'application/json'},body:data===undefined?undefined:JSON.stringify(data)});
const crmEscape=value=>String(value??'').replace(/[&<>"']/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
function crmError(error){const message=String(error?.message||error);try{const parsed=JSON.parse(message);return typeof parsed.detail==='string'?parsed.detail:message}catch{return message}}
function crmWritable(){return ['admin','operator'].includes(ME?.role)}
function crmSearchChanged(){clearTimeout(CRM_SEARCH_TIMER);CRM_SEARCH_TIMER=setTimeout(()=>crmRefreshList(),250)}
async function loadCrm(){
 document.querySelectorAll('#view-crm .crm-write').forEach(button=>button.hidden=!crmWritable());
 try{CRM_SITES=await json('/api/v1/sites')}catch{CRM_SITES=[]}
 await crmRefreshList();
 if(CRM_ACTIVE_ID)await crmOpenCustomer(CRM_ACTIVE_ID);
}
async function crmRefreshList(){
 const list=document.getElementById('crmList');if(!list)return;
 const query=document.getElementById('crmSearch')?.value||'';
 try{
  const customers=await crmApi('/customers?q='+encodeURIComponent(query));
  list.innerHTML=customers.length?customers.map(c=>`<button type="button" class="crm-customer-card ${CRM_ACTIVE_ID===c.id?'selected':''}" onclick="crmOpenCustomer(${Number(c.id)})"><strong>${crmEscape(c.name)}</strong><span>${crmEscape(c.status)} · ${Number(c.contact_count)} contact${Number(c.contact_count)===1?'':'s'}${c.site_name?' · '+crmEscape(c.site_name):''}</span><span class="crm-chevron" aria-hidden="true">›</span></button>`).join(''):'<div class="crm-empty">No customers found. Add a customer to create the first record.</div>';
 }catch(e){list.innerHTML='<div class="crm-error">Could not load customers: '+crmEscape(crmError(e))+'</div>'}
}
function crmNewCustomer(){CRM_ACTIVE_ID=null;CRM_CONTACT_EDIT=null;crmRefreshList();crmRenderCustomer({name:'',customer_type:'business',status:'active',email:'',phone:'',address:'',notes:'',site_id:null,contacts:[]})}
async function crmOpenCustomer(id){
 const record=document.getElementById('crmRecord');if(!record)return;
 CRM_ACTIVE_ID=id;CRM_CONTACT_EDIT=null;record.innerHTML='<div class="crm-empty">Loading customer…</div>';
 try{crmRenderCustomer(await crmApi('/customers/'+id));await crmRefreshList()}
 catch(e){record.innerHTML='<div class="crm-error">Could not load customer: '+crmEscape(crmError(e))+'</div>'}
}
function crmRenderCustomer(customer){
 const record=document.getElementById('crmRecord');if(!record)return;
 const existing=Number.isInteger(customer.id),writable=crmWritable(),disabled=writable?'':'disabled';
 const option=(value,label,selected)=>`<option value="${value}" ${value===selected?'selected':''}>${label}</option>`;
 const sites=`<option value="">No linked site</option>`+CRM_SITES.map(s=>`<option value="${Number(s.id)}" ${s.id===customer.site_id?'selected':''}>${crmEscape(s.name)}</option>`).join('');
 record.innerHTML=`<div class="crm-record-head"><div><h2>${crmEscape(existing?customer.name:'New customer')}</h2><p>Customer record ${existing?'· Created '+crmEscape(new Date(customer.created_at).toLocaleDateString()):'· Add the customer details below'}</p></div><div class="crm-record-actions">${existing&&ME?.role==='admin'?'<button class="danger" type="button" onclick="crmDeleteCustomer()">Delete</button>':''}${writable?'<button class="primary" type="submit" form="crmCustomerForm">Save customer</button>':''}</div></div>
 <form id="crmCustomerForm" onsubmit="return crmSaveCustomer(event)"><h3>Customer information</h3><div class="crm-fields">
 <label>Customer / company name<input class="input" name="name" value="${crmEscape(customer.name)}" required maxlength="160" ${disabled}></label>
 <label>Customer type<select class="filter" name="customer_type" ${disabled}>${option('business','Business',customer.customer_type)}${option('individual','Individual',customer.customer_type)}</select></label>
 <label>Contact email<input class="input" name="email" type="email" value="${crmEscape(customer.email)}" maxlength="254" ${disabled}></label>
 <label>Phone<input class="input" name="phone" type="tel" value="${crmEscape(customer.phone)}" maxlength="80" ${disabled}></label>
 <label>Service status<select class="filter" name="status" ${disabled}>${option('active','Active',customer.status)}${option('prospect','Prospect',customer.status)}${option('inactive','Inactive',customer.status)}</select></label>
 <label>Linked GODSEYE site<select class="filter" name="site_id" ${disabled}>${sites}</select></label>
 <label class="crm-full">Address<input class="input" name="address" value="${crmEscape(customer.address)}" maxlength="400" ${disabled}></label>
 <label class="crm-full">Internal notes<textarea class="input" name="notes" rows="4" maxlength="5000" ${disabled}>${crmEscape(customer.notes)}</textarea></label></div>
 <div class="crm-form-message" id="crmFormMessage" role="status"></div></form>
 <div class="crm-contact-heading"><h3>Contacts <span>${customer.contacts.length}</span></h3>${existing&&writable?'<button class="secondary" type="button" onclick="crmShowContactForm()">+ Add contact</button>':''}</div>
 <div class="crm-contacts">${customer.contacts.length?customer.contacts.map(contact=>`<div class="crm-contact-card"><div><b>${crmEscape(contact.name)}</b><p>${crmEscape([contact.role,contact.email,contact.phone].filter(Boolean).join(' · ')||'No contact details added')}</p></div>${writable?`<div class="crm-contact-actions"><button class="secondary" type="button" onclick="crmShowContactForm(${Number(contact.id)})">Edit</button><button class="danger" type="button" onclick="crmDeleteContact(${Number(contact.id)})">Remove</button></div>`:''}</div>`).join(''):'<div class="crm-empty">No contacts yet. Save the customer, then add a contact.</div>'}</div>
 <div id="crmContactEditor"></div>${customer.site_id?`<div class="crm-linked-site">Linked site: <b>${crmEscape(customer.site_name||'Site unavailable')}</b>${customer.site_status?' · '+crmEscape(customer.site_status):''} <button class="secondary" type="button" onclick="showView('sites',true)">Open Sites</button></div>`:''}`;
 record.dataset.customer=JSON.stringify(customer);
}
async function crmSaveCustomer(event){
 event.preventDefault();if(!crmWritable())return false;
 const form=event.target,button=recordButton(),message=document.getElementById('crmFormMessage');
 const data=Object.fromEntries(new FormData(form));data.site_id=data.site_id?Number(data.site_id):null;
 if(button)button.disabled=true;
 try{const customer=await crmApi(CRM_ACTIVE_ID?'/customers/'+CRM_ACTIVE_ID:'/customers',CRM_ACTIVE_ID?'PUT':'POST',data);CRM_ACTIVE_ID=customer.id;crmRenderCustomer(customer);await crmRefreshList();document.getElementById('crmFormMessage').textContent='Customer saved.'}
 catch(e){message.textContent='Could not save customer: '+crmError(e)}finally{if(button)button.disabled=false}
 return false;
}
function recordButton(){return document.querySelector('#crmRecord .crm-record-actions button[type=submit]')}
function crmShowContactForm(id=null){
 if(!CRM_ACTIVE_ID||!crmWritable())return;
 const customer=JSON.parse(document.getElementById('crmRecord').dataset.customer||'{}');
 const contact=customer.contacts?.find(c=>c.id===id)||{name:'',role:'',email:'',phone:''};CRM_CONTACT_EDIT=id;
 document.getElementById('crmContactEditor').innerHTML=`<form class="crm-contact-editor" onsubmit="return crmSaveContact(event)"><h3>${id?'Edit contact':'Add contact'}</h3><div class="crm-fields"><label>Name<input class="input" name="name" required maxlength="160" value="${crmEscape(contact.name)}"></label><label>Role<input class="input" name="role" maxlength="120" value="${crmEscape(contact.role)}"></label><label>Email<input class="input" name="email" type="email" maxlength="254" value="${crmEscape(contact.email)}"></label><label>Phone<input class="input" name="phone" type="tel" maxlength="80" value="${crmEscape(contact.phone)}"></label></div><div class="crm-form-message" role="status"></div><div class="crm-editor-actions"><button class="secondary" type="button" onclick="document.getElementById('crmContactEditor').replaceChildren()">Cancel</button><button class="primary" type="submit">Save contact</button></div></form>`;
 document.querySelector('#crmContactEditor [name=name]').focus();
}
async function crmSaveContact(event){
 event.preventDefault();const form=event.target,button=form.querySelector('[type=submit]');button.disabled=true;
 try{await crmApi(`/customers/${CRM_ACTIVE_ID}/contacts${CRM_CONTACT_EDIT?'/'+CRM_CONTACT_EDIT:''}`,CRM_CONTACT_EDIT?'PUT':'POST',Object.fromEntries(new FormData(form)));await crmOpenCustomer(CRM_ACTIVE_ID)}
 catch(e){form.querySelector('.crm-form-message').textContent='Could not save contact: '+crmError(e);button.disabled=false}
 return false;
}
async function crmDeleteContact(id){
 if(!confirm('Remove this contact from the customer?'))return;
 try{await crmApi(`/customers/${CRM_ACTIVE_ID}/contacts/${id}`,'DELETE');await crmOpenCustomer(CRM_ACTIVE_ID)}catch(e){alert('Could not remove contact: '+crmError(e))}
}
async function crmDeleteCustomer(){
 if(ME?.role!=='admin'||!CRM_ACTIVE_ID||!confirm('Delete this customer and all its contacts? This cannot be undone.'))return;
 try{await crmApi('/customers/'+CRM_ACTIVE_ID,'DELETE');CRM_ACTIVE_ID=null;document.getElementById('crmRecord').innerHTML='<div class="crm-empty">Customer deleted. Select another customer or add a new one.</div>';await crmRefreshList()}
 catch(e){alert('Could not delete customer: '+crmError(e))}
}
