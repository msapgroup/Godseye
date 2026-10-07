/* GODSEYE About-page legal notices; informational cards preserve existing access permissions. */
let ABOUT_LEGAL_KIND='notice',ABOUT_LEGAL_ORIGIN=null;
function openAboutLegal(kind='notice'){
 const dialog=document.getElementById('aboutLegalDialog');if(!dialog)return;
 const terms=kind==='terms';ABOUT_LEGAL_KIND=terms?'terms':'notice';
 document.getElementById('aboutLegalTitle').textContent=terms?'GODSEYE Terms of Use':'License & Legal Notice';
 document.getElementById('aboutLegalSubtitle').textContent=terms?'MSAP Group LLC':'GODSEYE · MSAP Group LLC';
 document.getElementById('aboutLegalNoticeContent').hidden=terms;
 document.getElementById('aboutLegalTermsContent').hidden=!terms;
 document.getElementById('aboutLegalSwitchLabel').textContent=terms?'License & Legal Notice':'Terms of Use';
 if(!dialog.open){ABOUT_LEGAL_ORIGIN=document.activeElement;dialog.showModal()}
 dialog.querySelector('.about-legal-body').scrollTop=0;
}
function switchAboutLegal(){openAboutLegal(ABOUT_LEGAL_KIND==='notice'?'terms':'notice')}
function closeAboutLegal(){document.getElementById('aboutLegalDialog')?.close()}
const aboutLegalDialog=document.getElementById('aboutLegalDialog');
aboutLegalDialog?.addEventListener('close',()=>{if(ABOUT_LEGAL_ORIGIN?.isConnected)ABOUT_LEGAL_ORIGIN.focus();ABOUT_LEGAL_ORIGIN=null});
aboutLegalDialog?.addEventListener('click',event=>{if(event.target!==aboutLegalDialog)return;const r=aboutLegalDialog.getBoundingClientRect();if(event.clientX<r.left||event.clientX>r.right||event.clientY<r.top||event.clientY>r.bottom)closeAboutLegal()});
aboutLegalDialog?.addEventListener('keydown',event=>{
 if(event.key!=='Tab')return;
 const items=[...aboutLegalDialog.querySelectorAll('a[href],button:not([disabled]),[tabindex="0"]')].filter(el=>el.getClientRects().length);
 if(!items.length)return;
 const first=items[0],last=items[items.length-1],active=document.activeElement;
 if(event.shiftKey&&(active===first||!aboutLegalDialog.contains(active))){event.preventDefault();last.focus()}
 else if(!event.shiftKey&&(active===last||!aboutLegalDialog.contains(active))){event.preventDefault();first.focus()}
});
