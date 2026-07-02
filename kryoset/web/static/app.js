const API='';
let currentUser=null,currentPath='',currentView='list',sortBy='name',sortDesc=false,renamingPath=null,memberTargetGroup=null,totpTargetUser=null,userStorageTarget=null;
const VIEW_KEY_PREFIX='kryoset:view:';
const CSRF_COOKIE='kryoset_csrf';

function escapeHtml(value){
  return String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',"'":'&#39;'}[c]));
}

function escapeAttr(value){
  return escapeHtml(value).replace(/`/g,'&#96;');
}

function escPath(p){
  return String(p ?? '')
    .replace(/&/g,'&amp;')
    .replace(/"/g,'&quot;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/\\/g,'\\\\')
    .replace(/'/g,"\\'")
    .replace(/\r/g,'\\r')
    .replace(/\n/g,'\\n');
}

function readCookie(name){
  const prefix=name+'=';
  for(const part of document.cookie.split(';')){
    const item=part.trim();
    if(item.startsWith(prefix))return decodeURIComponent(item.slice(prefix.length));
  }
  return '';
}

function csrfHeaders(){
  const token=readCookie(CSRF_COOKIE);
  return token?{'X-Kryoset-CSRF':token}:{};
}

function hide(el){if(el)el.classList.add('hidden')}
function show(el){if(el)el.classList.remove('hidden')}
function setVisible(el, visible){if(visible)show(el);else hide(el)}
function isHidden(el){return !el || el.classList.contains('hidden')}
function setPercent(el, pct){
  if(!el)return;
  const safe=Math.max(0, Math.min(100, Math.round(Number(pct)||0)));
  for(const cls of Array.from(el.classList)){if(cls.startsWith('pct-'))el.classList.remove(cls)}
  el.classList.add('pct-'+safe);
  el.setAttribute('aria-valuenow', String(safe));
}

async function api(method,path,body,isForm=false){
  const h={...csrfHeaders()};
  let rb;
  if(body&&!isForm){h['Content-Type']='application/json';rb=JSON.stringify(body)}
  else if(body&&isForm)rb=body;
  let resp=await fetch(API+path,{method,headers:h,body:rb,credentials:'same-origin'});
  if(resp.status===401){
    const ok=await tryRefresh();
    if(ok){
      Object.assign(h, csrfHeaders());
      resp=await fetch(API+path,{method,headers:h,body:rb,credentials:'same-origin'});
    }
  }
  return resp;
}

async function tryRefresh(){
  try{
    const r=await fetch('/auth/refresh',{method:'POST',headers:csrfHeaders(),credentials:'same-origin'});
    if(!r.ok){return false}
    await r.json().catch(()=>({}));
    return true;
  }catch{return false}
}

async function doLogin(){
  const username=document.getElementById('login-user').value.trim();
  const password=document.getElementById('login-pass').value;
  hide(document.getElementById('login-error'));
  const btn=document.getElementById('login-btn');btn.disabled=true;btn.textContent='…';
  try{
    const resp=await fetch('/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password})});
    const data=await resp.json().catch(()=>({detail:'Login failed.'}));
    if(!resp.ok){showLoginError(data.detail||'Login failed');return}
    if(data.totp_required){window._pendingTotpUser=username;window._pendingTotpToken=data.totp_token;hide(document.getElementById('login-form'));show(document.getElementById('totp-form'));document.getElementById('totp-code').focus();return}
    await finishLogin();
  }catch(error){
    showLoginError(error?.message||'Connection failed.');
  }finally{
    btn.disabled=false;btn.textContent='Connect';
  }
}

async function doTOTP(){
  const code=document.getElementById('totp-code').value.trim();
  hide(document.getElementById('totp-error'));
  const btn=document.getElementById('totp-btn');btn.disabled=true;
  try{
    const resp=await fetch('/auth/totp',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:window._pendingTotpUser,code,totp_token:window._pendingTotpToken})});
    const data=await resp.json().catch(()=>({detail:'Invalid code.'}));
    if(!resp.ok){const el=document.getElementById('totp-error');el.textContent=data.detail||'Invalid code';show(el);return}
    await finishLogin();
  }catch(error){
    const el=document.getElementById('totp-error');el.textContent=error?.message||'Connection failed.';show(el);
  }finally{
    btn.disabled=false;
  }
}

async function finishLogin(){
  const r=await api('GET','/auth/me');
  if(!r.ok){showLoginError('Session validation failed.');return}
  currentUser=await r.json();
  currentPath=normalizeInitialPath(currentUser.initial_path);
  document.getElementById('sidebar-username').textContent=currentUser.username;
  if(currentUser.admin){
    show(document.getElementById('sidebar-admin-tag'));
    document.querySelectorAll('.admin-only').forEach(el=>show(el));
  }
  restoreViewPreference();
  document.getElementById('login-screen').classList.add('hidden');
  document.getElementById('app').classList.remove('hidden');
  showPanel('files');
  updateSidebarQuota().catch(()=>{});
}

async function updateSidebarQuota(){
  const container=document.getElementById('sidebar-quota-container');
  const text=document.getElementById('sidebar-quota-text');
  const fill=document.getElementById('sidebar-quota-fill');
  if(!currentUser){
    hide(container);
    return;
  }

  if(currentUser.admin){
    hide(container);
    return;
  }

  if(!currentUser.quota_bytes){
    hide(container);
    return;
  }
  const quota=currentUser.quota_bytes;
  const used=currentUser.used_bytes;
  if(used===null||used===undefined){
    text.textContent='Usage not calculated / '+humanBytes(quota);
    setPercent(fill,0);
  }else{
    const ratio=quota>0?Math.min(100,Math.round(used/quota*100)):0;
    text.textContent=humanBytes(used)+' / '+humanBytes(quota);
    setPercent(fill,ratio);
  }
  show(container);
}

function showLoginError(msg){const el=document.getElementById('login-error');el.textContent=msg;show(el)}

function normalizeInitialPath(path){
  if(!path||path==='/'||path==='.')return '';
  return path.replace(/^\/+|\/+$/g,'');
}

async function doLogout(){
  await api('POST','/auth/logout').catch(()=>{});
  currentUser=null;currentPath='';
  document.getElementById('login-screen').classList.remove('hidden');
  document.getElementById('app').classList.add('hidden');
  show(document.getElementById('login-form'));
  hide(document.getElementById('totp-form'));
  document.getElementById('login-user').value='';document.getElementById('login-pass').value='';
  document.querySelectorAll('.admin-only').forEach(el=>hide(el));
  hide(document.getElementById('sidebar-admin-tag'));
  document.getElementById('settings-new-password').value='';
  document.getElementById('settings-new-password-confirm').value='';
}

function showPanel(name){
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
  const p=document.getElementById('panel-'+name);if(p)p.classList.add('active');
  const n=document.getElementById('nav-'+name);if(n)n.classList.add('active');
  if(name==='files')reloadFiles();
  if(name==='settings')loadSettings();
  if(name==='shares')loadShares();
  if(name==='users')loadUsers();
  if(name==='perms')loadPerms();
  if(name==='logs')loadLogs();
}

function getViewKey(){return VIEW_KEY_PREFIX+(currentUser?.username||'guest')}

function restoreViewPreference(){
  const saved=localStorage.getItem(getViewKey());
  setView(saved==='grid'?'grid':'list',false);
}

function setView(v,persist=true){
  currentView=v;
  document.getElementById('view-list-btn').classList.toggle('active',v==='list');
  document.getElementById('view-grid-btn').classList.toggle('active',v==='grid');
  setVisible(document.getElementById('file-list-view'), v==='list');
  setVisible(document.getElementById('file-grid-view'), v==='grid');
  if(persist)localStorage.setItem(getViewKey(),v);
}

function toggleSort(col){
  if(sortBy===col)sortDesc=!sortDesc;else{sortBy=col;sortDesc=false}
  document.getElementById('sort-select').value=col;
  ['name','size','modified'].forEach(c=>{const el=document.getElementById('sort-'+c+'-icon');if(el)el.textContent=c===sortBy?(sortDesc?' ↓':' ↑'):''});
  reloadFiles();
}

function buildBreadcrumb(){
  const el=document.getElementById('breadcrumb');
  const pd=document.getElementById('path-display');
  const parts=currentPath?currentPath.split('/').filter(Boolean):[];
  pd.textContent='/'+(currentPath||'');pd.title=pd.textContent;
  let html='<span class="breadcrumb-part" data-action="navigateTo" data-path="">~</span>';
  let acc='';
  for(let i=0;i<parts.length;i++){
    acc+=(acc?'/':'')+parts[i];
    const path=acc;
    html+='<span class="breadcrumb-sep">/</span>';
    if(i===parts.length-1)html+='<span class="breadcrumb-current">'+escapeHtml(parts[i])+'</span>';
    else html+='<span class="breadcrumb-part" data-action="navigateTo" data-path="'+escapeAttr(path)+'" title="'+escapeAttr(path)+'">'+escapeHtml(parts[i])+'</span>';
  }
  el.innerHTML=html;
}

function navigateTo(path){currentPath=path;reloadFiles()}

function getFileIcon(e){
  if(e.isParent)return'<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M15 18l-6-6 6-6"/></svg>';
  if(e.type==='directory')return'<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>';
  const ext=(e.name.split('.').pop()||'').toLowerCase();
  const imgExts=['jpg','jpeg','png','gif','webp','svg','bmp','ico','tif','tiff','avif','jfif','heic','heif'];
  if(imgExts.includes(ext))return'<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>';
  const videoExts=['mp4','mkv','webm','mov','avi'];
  if(videoExts.includes(ext))return'<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#8b5cf6" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polygon points="23 7 16 12 23 17 23 7"/><rect x="1" y="5" width="15" height="14" rx="2"/></svg>';
  const audioExts=['mp3','ogg','wav','flac','aac'];
  if(audioExts.includes(ext))return'<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#ec4899" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/></svg>';
  const archiveExts=['zip','tar','gz','bz2','xz','rar','7z'];
  if(archiveExts.includes(ext))return'<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#f97316" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="21 8 21 21 3 21 3 8"/><rect x="1" y="3" width="22" height="5"/><line x1="10" y1="12" x2="14" y2="12"/></svg>';
  const codeExts=['js','ts','py','sh','json','html','css','php','rb','go','rs','c','cpp','h','java','yaml','yml','toml','xml'];
  if(codeExts.includes(ext))return'<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#06b6d4" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>';
  const docExts=['doc','docx','odt'];
  if(docExts.includes(ext))return'<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>';
  const sheetExts=['xls','xlsx','csv','ods'];
  if(sheetExts.includes(ext))return'<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="8" y1="13" x2="16" y2="13"/><line x1="8" y1="17" x2="16" y2="17"/><line x1="12" y1="9" x2="12" y2="21"/></svg>';
  if(ext==='pdf')return'<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><path d="M10 13a2 2 0 0 1 4 0v2a2 2 0 0 1-4 0"/></svg>';
  return'<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>';
}
function formatSize(b){if(b===null||b===undefined)return'—';const u=['B','KB','MB','GB','TB'];let i=0;while(b>=1024&&i<u.length-1){b/=1024;i++}return b.toFixed(i>0?1:0)+' '+u[i]}
function formatDate(ts){if(!ts)return'—';const d=new Date(ts*1000);return d.toLocaleDateString()+' '+d.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})}

function humanBytes(bytes){
  if(bytes===null||bytes===undefined)return'Unlimited';
  const units=['B','KB','MB','GB','TB'];
  let value=bytes;
  let unitIndex=0;
  while(value>=1024&&unitIndex<units.length-1){value/=1024;unitIndex++}
  return value.toFixed(unitIndex===0?0:1)+' '+units[unitIndex];
}

function renderActivity(containerId, emptyId, items, label){
  const container=document.getElementById(containerId);
  const empty=document.getElementById(emptyId);
  if(!container||!empty)return;
  container.innerHTML='';
  if(!items.length){show(empty);return}
  hide(empty);
  for(const item of items){
    const div=document.createElement('div');
    div.className='activity-item';
    div.innerHTML='<div class="activity-main"><div class="activity-type">'+escapeHtml(label)+' · '+escapeHtml(String(item.event||'').replace(/_/g,' '))+'</div><div class="activity-time">'+escapeHtml(item.timestamp||'')+'</div></div><div class="activity-ip">'+escapeHtml(item.ip||'')+'</div>';
    container.appendChild(div);
  }
}

async function updateSettingsStorageCard(){
  const quotaSummary=document.getElementById('settings-quota-summary');
  const quotaDetail=document.getElementById('settings-quota-detail');
  const quotaFill=document.getElementById('settings-quota-fill');
  const storageNote=document.getElementById('settings-storage-note');
  if(!quotaSummary||!quotaDetail||!quotaFill||!storageNote)return;

  if(currentUser?.admin){
    const resp=await api('GET','/storage/status');
    if(!resp.ok){
      quotaSummary.textContent='Global storage usage unavailable';
      quotaDetail.textContent='Unable to load the global Kryoset budget right now.';
      setPercent(quotaFill,0);
      storageNote.textContent='Admin view: this card shows usage across all users versus Kryoset global budget.';
      return;
    }
    const globalStatus=await resp.json();
    const used=globalStatus.used_bytes||0;
    const globalMax=globalStatus.global_max_bytes;
    if(globalMax===null||globalMax===undefined){
      quotaSummary.textContent='Kryoset used: '+humanBytes(used)+' / Unlimited';
      quotaDetail.textContent='No global budget configured for Kryoset.';
      setPercent(quotaFill,0);
    }else{
      const ratio=globalMax>0?Math.min(100,Math.round(used/globalMax*100)):0;
      quotaSummary.textContent='Kryoset used: '+humanBytes(used)+' / '+humanBytes(globalMax);
      quotaDetail.textContent=ratio+'% of global Kryoset budget used';
      setPercent(quotaFill,ratio);
    }
    storageNote.textContent='Admin view: this card shows usage across all users versus Kryoset global budget.';
    return;
  }

  const quota=currentUser?.quota_bytes;
  const used=currentUser?.used_bytes;
  if(quota===null||quota===undefined){
    quotaSummary.textContent=(used===null||used===undefined?'Usage not calculated':'Used: '+humanBytes(used))+' / Unlimited';
    quotaDetail.textContent='No storage limit configured for this account.';
    setPercent(quotaFill,0);
  }else if(used===null||used===undefined){
    quotaSummary.textContent='Usage not calculated / '+humanBytes(quota);
    quotaDetail.textContent='Open storage settings or upload/delete a file to refresh the cached usage.';
    setPercent(quotaFill,0);
  }else{
    const ratio=quota>0?Math.min(100,Math.round(used/quota*100)):0;
    quotaSummary.textContent='Used: '+humanBytes(used)+' / '+humanBytes(quota);
    quotaDetail.textContent=ratio+'% of quota used';
    setPercent(quotaFill,ratio);
  }
  storageNote.textContent='This reflects the personal storage quota for your account when one is configured.';
}

async function loadSettings(){
  const resp=await api('GET','/auth/me');
  if(!resp.ok){toast('Cannot load settings','error');return}
  currentUser=await resp.json();
  document.getElementById('settings-username').textContent=currentUser.username;
  document.getElementById('settings-role').textContent=currentUser.admin?'admin':'user';
  document.getElementById('settings-totp-status').textContent=currentUser.totp_enabled?'Enabled':'Disabled';
  document.getElementById('settings-last-refresh').textContent=new Date().toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
  await updateSettingsStorageCard();
  await updateSidebarQuota();
  renderActivity('settings-logins','settings-logins-empty',currentUser.recent_logins||[],'Login');
  renderActivity('settings-failures','settings-failures-empty',currentUser.recent_failures||[],'Failure');
}

async function doChangeMyPassword(){
  const password=document.getElementById('settings-new-password').value;
  const confirmPassword=document.getElementById('settings-new-password-confirm').value;
  const msg=document.getElementById('settings-password-msg');
  hide(msg);
  if(!password||!confirmPassword){msg.textContent='Enter the new password twice.';show(msg);return}
  if(password!==confirmPassword){msg.textContent='Passwords do not match.';show(msg);return}
  const resp=await api('POST','/users/'+currentUser.username+'/password',{new_password:password});
  if(resp.ok){toast('Password updated','success');document.getElementById('settings-new-password').value='';document.getElementById('settings-new-password-confirm').value=''}
  else{const d=await resp.json();msg.textContent=d.detail||'Password update failed.';show(msg)}
}

function setupMyTOTP(){if(currentUser?.username)setupTOTP(currentUser.username)}
async function disableMyTOTP(){if(!currentUser?.username)return;await disableTOTP(currentUser.username);if(document.getElementById('panel-settings').classList.contains('active'))loadSettings()}

async function reloadFiles(){
  buildBreadcrumb();
  const showHidden=document.getElementById('show-hidden')?.checked||false;
  const sort=document.getElementById('sort-select')?.value||sortBy;sortBy=sort;
  const resp=await api('GET','/files/list?path='+encodeURIComponent(currentPath)+'&show_hidden='+showHidden+'&sort_by='+sort+'&sort_desc='+sortDesc);
  if(!resp.ok){const d=await resp.json().catch(()=>({}));toast(d.detail||'Cannot list directory','error');return}
  const data=await resp.json();renderFiles(data.entries||[]);
}


function renderFiles(entries){
  const empty=document.getElementById('files-empty');
  const tbody=document.getElementById('file-list');
  const grid=document.getElementById('file-grid');
  const parentRow=currentPath?[{name:'..',type:'directory',size:null,modified:null,previewable:false,isParent:true}]:[];
  const all=[...parentRow,...entries];
  setVisible(empty, entries.length===0&&!currentPath);
  tbody.innerHTML='';grid.innerHTML='';
  for(const entry of all){
    const entryPath=entry.isParent?(currentPath.includes('/')?currentPath.substring(0,currentPath.lastIndexOf('/')):''):(currentPath?currentPath+'/'+entry.name:entry.name);
    const attrPath=escapeAttr(entryPath);
    const attrName=escapeAttr(entry.name);
    const icon=getFileIcon(entry);const isDir=entry.type==='directory';
    const primaryAction=isDir||entry.isParent?'navigateTo':(entry.previewable?'previewFile':'downloadFile');
    const primaryAttrs='data-action="'+primaryAction+'" data-path="'+attrPath+'"'+(entry.previewable?' data-name="'+attrName+'"':'');

    const tr=document.createElement('tr');
    tr.innerHTML=
      '<td><div class="file-name-cell" '+primaryAttrs+'><span class="file-icon">'+icon+'</span>'+
      '<span class="file-name-text">'+escapeHtml(entry.name)+'</span></div></td>'+
      '<td class="file-size">'+formatSize(entry.size)+'</td>'+
      '<td class="file-date">'+formatDate(entry.modified)+'</td>'+
      '<td>'+(entry.isParent?'':'<div class="row-actions">'+
      ((!isDir&&entry.previewable)?'<button class="btn btn-ghost btn-sm" data-action="previewFile" data-path="'+attrPath+'" data-name="'+attrName+'" title="Preview"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg></button>':'')+
      (!isDir?'<button class="btn btn-ghost btn-sm" data-action="downloadFile" data-path="'+attrPath+'" title="Download">↓</button>':'')+
      (!isDir?'<button class="btn btn-ghost btn-sm" data-action="promptShare" data-path="'+attrPath+'" title="Share">&#8677;</button>':'')+
      '<button class="btn btn-ghost btn-sm" data-action="promptRename" data-path="'+attrPath+'" title="Rename">✎</button>'+
      '<button class="btn btn-danger btn-sm" data-action="showDeleteConfirm" data-path="'+attrPath+'" data-is-dir="'+String(isDir)+'" title="Delete">✕</button>'+
      '</div>')+'</td>';
    tbody.appendChild(tr);

    const div=document.createElement('div');
    div.className='grid-item';
    div.setAttribute('data-action', primaryAction);
    div.setAttribute('data-path', entryPath);
    if(entry.previewable)div.setAttribute('data-name', entry.name);
    div.innerHTML=
      '<span class="grid-icon">'+icon+'</span>'+
      '<div class="grid-name">'+escapeHtml(entry.name)+'</div>'+
      '<div class="grid-size">'+(!isDir?formatSize(entry.size):'')+'</div>'+
      (entry.isParent?'':'<div class="grid-actions">'+
      (!isDir&&entry.previewable?'<div class="grid-action-btn" data-action="previewFile" data-path="'+attrPath+'" data-name="'+attrName+'" title="Preview"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg></div>':'')+
      (!isDir?'<div class="grid-action-btn" data-action="downloadFile" data-path="'+attrPath+'" title="Download">↓</div>':'')+
      '<div class="grid-action-btn" data-action="promptRename" data-path="'+attrPath+'" title="Rename">✎</div>'+
      '<div class="grid-action-btn" data-action="showDeleteConfirm" data-path="'+attrPath+'" data-is-dir="'+String(isDir)+'" title="Delete">✕</div>'+
      '</div>');
    grid.appendChild(div);
  }
}

async function previewFile(path,name){
  document.getElementById('preview-title').textContent=name;
  const area=document.getElementById('preview-area');
  const modal=document.getElementById('preview-modal');
  modal.classList.remove('preview-fit');
  area.classList.remove('preview-media-mode');
  area.innerHTML='<div class="preview-message">Loading…</div>';
  const previewDownloadBtn=document.getElementById('preview-download-btn');
  previewDownloadBtn.dataset.action='downloadFile';
  previewDownloadBtn.dataset.path=path;
  openModal('preview-modal');
  const ext=(name.split('.').pop()||'').toLowerCase();
  const url='/files/preview?path='+encodeURIComponent(path);
  const resp=await fetch(url,{credentials:'same-origin'});
  if(!resp.ok){area.innerHTML='<div class="preview-error">Cannot preview this file.</div>';return}
  const blob=await resp.blob();const objUrl=URL.createObjectURL(blob);
  const mime=(blob.type||'').toLowerCase();
  if(mime.startsWith('image/')||['jpg','jpeg','png','gif','webp','svg','bmp','ico','tif','tiff','avif','jfif','heic','heif'].includes(ext)){
    modal.classList.add('preview-fit');
    area.classList.add('preview-media-mode');
    area.innerHTML='<img src="'+objUrl+'" alt="'+escapeHtml(name)+'">';
  }else if(mime.startsWith('video/')||['mp4','webm','mov','m4v'].includes(ext)){
    modal.classList.add('preview-fit');
    area.classList.add('preview-media-mode');
    area.innerHTML='<video controls playsinline preload="metadata" src="'+objUrl+'"></video>';
  }
  else if(mime.startsWith('audio/')||['mp3','ogg','wav'].includes(ext))area.innerHTML='<audio class="preview-audio" controls src="'+objUrl+'"></audio>';
  else if(mime==='application/pdf'||ext==='pdf')area.innerHTML='<iframe class="preview-frame" src="'+objUrl+'"></iframe>';
  else{const text=await blob.text();area.innerHTML='<pre>'+escapeHtml(text).substring(0,80000)+'</pre>'}
}

async function downloadFile(path){
  const resp=await api('GET','/files/download?path='+encodeURIComponent(path));
  if(!resp.ok){const d=await resp.json();toast(d.detail,'error');return}
  const blob=await resp.blob();const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=path.split('/').pop();a.click();
}
let pendingDeletePath=null;
let pendingDeleteIsDir=false;
function showDeleteConfirm(path,isDir){
  pendingDeletePath=path;
  pendingDeleteIsDir=!!isDir;
  const details=document.getElementById('delete-confirm-details');
  if(details)details.textContent='Delete "'+path+'"?'+(isDir?' This will delete all contents.':'');
  openModal('delete-confirm-modal');
}
async function doDeleteConfirm(){
  if(!pendingDeletePath){closeModal('delete-confirm-modal');return}
  const path=pendingDeletePath;
  const isDir=pendingDeleteIsDir;
  pendingDeletePath=null;
  pendingDeleteIsDir=false;
  closeModal('delete-confirm-modal');
  await deleteEntry(path,isDir);
}
async function deleteEntry(path,isDir){
  const resp=await api('DELETE','/files/delete?path='+encodeURIComponent(path));
  if(resp.ok){toast('Deleted','success');reloadFiles();refreshQuotaDisplay()}else{const d=await resp.json();toast(d.detail,'error')}
}

async function refreshQuotaDisplay(){
  if(currentUser?.admin){
    if(document.getElementById('panel-settings').classList.contains('active')){
      await updateSettingsStorageCard();
    }
    return;
  }

  const resp=await api('GET','/auth/quota');
  if(!resp.ok)return;
  const data=await resp.json();
  const quota=data.quota_bytes;
  const used=data.used_bytes;
  const container=document.getElementById('sidebar-quota-container');
  const text=document.getElementById('sidebar-quota-text');
  const fill=document.getElementById('sidebar-quota-fill');
  if(container&&text&&fill){
    if(quota){
      if(used===null||used===undefined){
        text.textContent='Usage not calculated / '+humanBytes(quota);
        setPercent(fill,0);
      }else{
        const ratio=quota>0?Math.min(100,Math.round(used/quota*100)):0;
        text.textContent=humanBytes(used)+' / '+humanBytes(quota);
        setPercent(fill,ratio);
      }
      show(container);
    }else{
      hide(container);
    }
  }
  const quotaSummary=document.getElementById('settings-quota-summary');
  const quotaDetail=document.getElementById('settings-quota-detail');
  const quotaFill=document.getElementById('settings-quota-fill');
  if(quotaSummary&&quotaDetail&&quotaFill){
    if(quota===null||quota===undefined){
      quotaSummary.textContent=(used===null||used===undefined?'Usage not calculated':'Used: '+humanBytes(used))+' / Unlimited';
      quotaDetail.textContent='No storage limit configured for this account.';
      setPercent(quotaFill,0);
    }else if(used===null||used===undefined){
      quotaSummary.textContent='Usage not calculated / '+humanBytes(quota);
      quotaDetail.textContent='Open storage settings or upload/delete a file to refresh the cached usage.';
      setPercent(quotaFill,0);
    }else{
      const ratio=quota>0?Math.min(100,Math.round(used/quota*100)):0;
      quotaSummary.textContent='Used: '+humanBytes(used)+' / '+humanBytes(quota);
      quotaDetail.textContent=ratio+'% of quota used';
      setPercent(quotaFill,ratio);
    }
  }
}

function promptRename(path){renamingPath=path;document.getElementById('rename-new').value=path.split('/').pop();openModal('rename-modal')}
async function doRename(){
  const newName=document.getElementById('rename-new').value.trim();if(!newName)return;
  const parent=renamingPath.includes('/')?renamingPath.substring(0,renamingPath.lastIndexOf('/')):'';
  const dest=parent?parent+'/'+newName:newName;
  const resp=await api('POST','/files/rename',{source:renamingPath,destination:dest});
  if(resp.ok){toast('Renamed','success');closeModal('rename-modal');reloadFiles()}else{const d=await resp.json();toast(d.detail,'error')}
}
function showMkdirModal(){document.getElementById('mkdir-name').value='';openModal('mkdir-modal')}
async function doMkdir(){
  const name=document.getElementById('mkdir-name').value.trim();if(!name)return;
  const path=currentPath?currentPath+'/'+name:name;
  const resp=await api('POST','/files/mkdir',{path});
  if(resp.ok){toast('Folder created','success');closeModal('mkdir-modal');reloadFiles()}else{const d=await resp.json();toast(d.detail,'error')}
}

const dropzone=document.getElementById('dropzone');
dropzone.addEventListener('dragover',e=>{e.preventDefault();dropzone.classList.add('drag-over')});
dropzone.addEventListener('dragleave',()=>dropzone.classList.remove('drag-over'));
dropzone.addEventListener('drop',e=>{e.preventDefault();dropzone.classList.remove('drag-over');handleUpload(e.dataTransfer.files)});
dropzone.addEventListener('click',()=>document.getElementById('upload-input').click());

function handleUpload(files){if(!files.length)return;for(const f of files)uploadSingleFile(f)}
function uploadSingleFile(file){
  const tray=document.getElementById('upload-tray');
  const path=currentPath?currentPath+'/'+file.name:file.name;
  const itemId='u'+Date.now()+Math.random().toString(36).slice(2);
  const item=document.createElement('div');item.className='upload-item';item.id=itemId;
  item.innerHTML='<div class="upload-item-name">'+escapeHtml(file.name)+'</div><div class="upload-item-bar"><div class="upload-item-fill pct-0" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0"></div></div><div class="upload-item-status"><span class="st">Uploading…</span><span>'+formatSize(file.size)+'</span></div>';
  tray.appendChild(item);
  const xhr=new XMLHttpRequest();xhr.open('POST','/files/upload?path='+encodeURIComponent(path));
  const csrf=readCookie(CSRF_COOKIE);if(csrf)xhr.setRequestHeader('X-Kryoset-CSRF',csrf);
  xhr.upload.addEventListener('progress',e=>{if(e.lengthComputable){const p=Math.round(e.loaded/e.total*100);const fill=item.querySelector('.upload-item-fill');const st=item.querySelector('.st');setPercent(fill,p);if(st)st.textContent=p+'%'}});
  const fd=new FormData();fd.append('file',file);xhr.send(fd);
  xhr.addEventListener('load',()=>{
    const fill=item.querySelector('.upload-item-fill');const st=item.querySelector('.st');
    if(xhr.status===201){item.classList.add('done');setPercent(fill,100);if(st)st.textContent='Done';reloadFiles();refreshQuotaDisplay()}
    else{item.classList.add('error');if(st)st.textContent='Error';try{const d=JSON.parse(xhr.responseText);toast(d.detail,'error')}catch{toast('Upload failed','error')}}
    setTimeout(()=>item.remove(),4000);
  });
  xhr.addEventListener('error',()=>{item.classList.add('error');const st=item.querySelector('.st');if(st)st.textContent='Failed';setTimeout(()=>item.remove(),4000)});
}

function promptShare(path){document.getElementById('share-path').value=path;document.getElementById('share-expires').value='';document.getElementById('share-limit').value='';document.getElementById('share-password').value='';openModal('share-modal')}
function showCreateShareModal(){document.getElementById('share-path').value='';document.getElementById('share-expires').value='';document.getElementById('share-limit').value='';document.getElementById('share-password').value='';openModal('share-modal')}
async function doCreateShare(){
  const path=document.getElementById('share-path').value.trim();
  const expiresStr=document.getElementById('share-expires').value;
  const limit=document.getElementById('share-limit').value;
  const password=document.getElementById('share-password').value;
  if(!path){toast('Path required','error');return}
  let expires_at=null;
  if(expiresStr){const m=expiresStr.match(/^(\d+)(h|d)$/);if(m){const ms=parseInt(m[1])*(m[2]==='h'?3600000:86400000);expires_at=new Date(Date.now()+ms).toISOString()}}
  const body={path,permissions:['DOWNLOAD'],...(expires_at&&{expires_at}),...(limit&&{download_limit:parseInt(limit)}),...(password&&{password})};
  const resp=await api('POST','/shares/',body);
  if(resp.ok){toast('Share link created!','success');closeModal('share-modal');showPanel('shares')}
  else{const d=await resp.json();toast(d.detail,'error')}
}
async function loadShares(){
  const resp=await api('GET','/shares/');if(!resp.ok){toast('Cannot load shares','error');return}
  const shares=await resp.json();
  const container=document.getElementById('shares-list');const empty=document.getElementById('shares-empty');
  container.innerHTML='';setVisible(empty, !shares.length);
  for(const share of shares){
    const url=location.origin+'/share/'+share.token;
    const tag=share.valid?'<span class="tag tag-valid">active</span>':'<span class="tag tag-expired">expired</span>';
    const passTag=share.password_protected?'<span class="tag tag-warn"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></span>':'';
    const dlInfo=share.download_limit?share.download_count+'/'+share.download_limit+' DL':share.download_count+' DL';
    const expires=share.expires_at?new Date(share.expires_at).toLocaleDateString():'Never';
    const safePath=escapeHtml(share.path);
    const safeCreator=escapeHtml(share.created_by);
    const safeUrl=escapeHtml(url);
    const attrToken=escapeAttr(share.token);
    const attrUrl=escapeAttr(url);
    const div=document.createElement('div');div.className='share-card';
    div.innerHTML=`<div class="share-header"><div class="share-info"><div class="share-path">${tag}${passTag} ${safePath}</div><div class="share-meta"><span><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg> ${escapeHtml(expires)}</span><span><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg> ${escapeHtml(dlInfo)}</span><span><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg> ${safeCreator}</span></div></div><button class="btn btn-danger btn-sm" data-action="revokeShare" data-token="${attrToken}">Revoke</button></div><div class="share-url-box"><span class="share-url">${safeUrl}</span><span class="copy-btn" data-action="copyText" data-text="${attrUrl}"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg> Copy</span></div>`;
    container.appendChild(div);
  }
}
async function revokeShare(token){
  if(!confirm('Revoke this share link?'))return;
  const resp=await api('DELETE','/shares/'+token);
  if(resp.ok){toast('Revoked','success');loadShares()}else{const d=await resp.json();toast(d.detail,'error')}
}
function copyText(t){navigator.clipboard.writeText(t).then(()=>toast('Copied!','success'))}

function parseStorageLimit(raw, unit){
  if(raw==='')return null;
  if(!/^\d+(\.\d+)?$/.test(raw))return 'invalid';
  const amount=parseFloat(raw);
  const factor=unit==='GB'?1024**3:1024**2;
  return Math.round(amount*factor);
}

function bytesToStorageInput(bytes){
  if(bytes===null||bytes===undefined)return {value:'',unit:'GB'};
  const gb=1024**3;
  if(bytes%gb===0)return {value:String(bytes/gb),unit:'GB'};
  return {value:(bytes/(1024**2)).toFixed(2).replace(/\.00$/,''),unit:'MB'};
}

async function loadUsers(){
  const resp=await api('GET','/users/');if(!resp.ok)return;
  const users=await resp.json();const tbody=document.getElementById('users-list');tbody.innerHTML='';
  for(const u of users){
    const tr=document.createElement('tr');
    const storageLabel=u.storage_max_bytes===null||u.storage_max_bytes===undefined?'Unlimited':humanBytes(u.storage_max_bytes);
    const safeUsername=escapeHtml(u.username);
    const attrUsername=escapeAttr(u.username);
    const storageMaxAttr=u.storage_max_bytes===null||u.storage_max_bytes===undefined?'':String(u.storage_max_bytes);
    tr.innerHTML=`<td class="mono-cell">${safeUsername}</td><td><span class="tag ${u.enabled?'tag-valid':'tag-expired'}">${u.enabled?'active':'disabled'}</span></td><td>${u.admin?'<span class="tag tag-warn">admin</span>':'<span class="muted-mono">user</span>'}</td><td><span class="storage-value">${escapeHtml(storageLabel)}</span></td><td>${u.totp_enabled?'<span class="tag tag-valid">2FA ✓</span>':'<span class="muted-mono">—</span>'}</td><td><div class="table-actions"><button class="btn btn-ghost btn-sm" data-action="showSetUserStorageModal" data-username="${attrUsername}" data-storage-max="${storageMaxAttr}">Storage</button><button class="btn btn-ghost btn-sm" data-action="toggleUser" data-username="${attrUsername}" data-enabled="${String(u.enabled)}">${u.enabled?'Disable':'Enable'}</button>${!u.totp_enabled?`<button class="btn btn-ghost btn-sm" data-action="setupTOTP" data-username="${attrUsername}">Setup 2FA</button>`:`<button class="btn btn-ghost btn-sm" data-action="disableTOTP" data-username="${attrUsername}">Disable 2FA</button>`}<button class="btn btn-ghost btn-sm" data-action="resetPwd" data-username="${attrUsername}">Reset pwd</button><button class="btn btn-danger btn-sm" data-action="deleteUser" data-username="${attrUsername}">✕</button></div></td>`;
    tbody.appendChild(tr);
  }
}
async function showCreateUserModal(){
  document.getElementById('new-username').value='';
  document.getElementById('new-password').value='';
  document.getElementById('new-home-path').value='';
  document.getElementById('new-storage-max').value='';
  document.getElementById('new-storage-max-unit').value='GB';
  document.getElementById('new-is-admin').checked=false;
  const groupSelect=document.getElementById('new-group-name');
  groupSelect.innerHTML='<option value="">None</option>';
  const groupsResp=await api('GET','/permissions/groups');
  if(groupsResp.ok){
    const groups=await groupsResp.json();
    for(const g of groups){
      const opt=document.createElement('option');
      opt.value=g.name;
      opt.textContent=g.name;
      groupSelect.appendChild(opt);
    }
  }
  openModal('user-modal')
}
async function doCreateUser(){
  const username=document.getElementById('new-username').value.trim();const password=document.getElementById('new-password').value;const homePath=document.getElementById('new-home-path').value.trim();const groupName=document.getElementById('new-group-name').value;const isAdmin=document.getElementById('new-is-admin').checked;const storageMaxRaw=document.getElementById('new-storage-max').value.trim();const storageMaxUnit=document.getElementById('new-storage-max-unit').value;
  const payload={username,password};
  if(homePath!=='')payload.home_path=homePath;
  if(groupName!=='')payload.group_name=groupName;
  const storageMaxBytes=parseStorageLimit(storageMaxRaw,storageMaxUnit);
  if(storageMaxBytes==='invalid'){toast('Storage max must be a non-negative number','error');return}
  if(storageMaxBytes!==null)payload.storage_max_bytes=storageMaxBytes;
  const resp=await api('POST','/users/',payload);
  if(!resp.ok){const d=await resp.json();toast(d.detail,'error');return}
  if(isAdmin)await api('POST','/users/'+username+'/admin?grant=true');
  toast('User "'+username+'" created','success');closeModal('user-modal');loadUsers();
}
function showSetUserStorageModal(username,currentStorageMax){
  userStorageTarget=username;
  document.getElementById('user-storage-user').textContent=username;
  const parsed=bytesToStorageInput(currentStorageMax===null||currentStorageMax===undefined?null:Number(currentStorageMax));
  document.getElementById('user-storage-max').value=parsed.value;
  document.getElementById('user-storage-max-unit').value=parsed.unit;
  openModal('user-storage-modal');
}
async function doSetUserStorage(){
  const raw=document.getElementById('user-storage-max').value.trim();
  const unit=document.getElementById('user-storage-max-unit').value;
  const bytes=parseStorageLimit(raw,unit);
  if(bytes==='invalid'){toast('Storage max must be a non-negative number','error');return}
  const payload={bytes_allocated:bytes};
  const resp=await api('PUT','/storage/allocations/user/'+userStorageTarget,payload);
  if(resp.ok){toast('Storage max updated','success');closeModal('user-storage-modal');loadUsers()}else{const d=await resp.json();toast(d.detail,'error')}
}
async function toggleUser(username,enabled){const action=enabled?'disable':'enable';const resp=await api('POST','/users/'+username+'/'+action);if(resp.ok){toast('User '+action+'d','success');loadUsers()}else{const d=await resp.json();toast(d.detail,'error')}}
async function resetPwd(username){if(!confirm('Reset password for "'+username+'"?'))return;const resp=await api('POST','/users/'+username+'/reset-password');if(resp.ok){const d=await resp.json();alert('New temporary password for '+username+':\n\n'+d.temporary_password+'\n\nShare this securely.')}else{const d=await resp.json();toast(d.detail,'error')}}
async function deleteUser(username){if(!confirm('Delete user "'+username+'"?'))return;const resp=await api('DELETE','/users/'+username);if(resp.ok){toast('User deleted','success');loadUsers()}else{const d=await resp.json();toast(d.detail,'error')}}
async function setupTOTP(username){
  totpTargetUser=username;
  document.getElementById('totp-modal-user').textContent=username;
  document.getElementById('totp-confirm-code').value='';
  hide(document.getElementById('totp-confirm-error'));
  document.getElementById('totp-qr-img').src='';
  document.getElementById('totp-secret-display').textContent='Loading…';
  openModal('totp-modal');
  const resp=await api('POST','/users/'+username+'/totp/setup');
  if(!resp.ok){const d=await resp.json();toast(d.detail,'error');closeModal('totp-modal');return}
  const data=await resp.json();
  document.getElementById('totp-qr-img').src='data:image/png;base64,'+data.qr_code_png_b64;
  document.getElementById('totp-secret-display').textContent=data.secret;
}
async function doTOTPConfirm(){
  const code=document.getElementById('totp-confirm-code').value.trim();
  hide(document.getElementById('totp-confirm-error'));
  const resp=await api('POST','/users/'+totpTargetUser+'/totp/confirm',{code});
  if(resp.ok){toast('2FA enabled','success');closeModal('totp-modal');loadUsers();if(document.getElementById('panel-settings').classList.contains('active'))loadSettings()}
  else{const d=await resp.json();const el=document.getElementById('totp-confirm-error');el.textContent=d.detail||'Invalid code';show(el)}
}
async function disableTOTP(username){if(!confirm('Disable 2FA for "'+username+'"?'))return;const resp=await api('DELETE','/users/'+username+'/totp');if(resp.ok){toast('2FA disabled','success');loadUsers()}else{const d=await resp.json();toast(d.detail,'error')}}

const ALL_PERMS=['LIST','PREVIEW','DOWNLOAD','UPLOAD','COPY','RENAME','MOVE','DELETE','MANAGE_PERMS','SHARE'];
let _cachedUsers=[],_cachedGroups=[];
async function loadPerms(){
  const [rr,gr]=await Promise.all([api('GET','/permissions/rules'),api('GET','/permissions/groups')]);
  if(!rr.ok||!gr.ok){toast('Cannot load permissions','error');return}
  const rules=await rr.json();const groups=await gr.json();_cachedGroups=groups;
  const gl=document.getElementById('groups-list');gl.innerHTML='';
  if(!groups.length)gl.innerHTML='<div class="empty-state empty-state-compact"><span class="empty-icon"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg></span>No groups yet</div>';
  for(const g of groups){
    const div=document.createElement('div');div.className='group-card';
    const attrGroup=escapeAttr(g.name);
    const safeGroup=escapeHtml(g.name);
    const mh=g.members.length?g.members.map(m=>`<span class="member-tag">${escapeHtml(m)}<span class="member-remove" data-action="removeMember" data-group="${attrGroup}" data-username="${escapeAttr(m)}">✕</span></span>`).join(''):'<span class="empty-member">empty</span>';
    const storageLabel=g.storage_max_bytes===null||g.storage_max_bytes===undefined?'Unlimited':humanBytes(g.storage_max_bytes);
    const homeMeta=g.home_path?`Home: ${escapeHtml(g.home_path)}${g.home_auto_user_subdir?'/&lt;username&gt;':''}`:'Home: none';
    div.innerHTML=`<div class="group-header"><span class="group-name"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg> ${safeGroup}</span><button class="btn btn-ghost btn-sm" data-action="showAddMemberModal" data-group="${attrGroup}">+ Member</button><button class="btn btn-danger btn-sm" data-action="deleteGroup" data-group="${attrGroup}">✕</button></div><div class="group-meta">Storage max: <span class="storage-value">${escapeHtml(storageLabel)}</span> · ${homeMeta}</div><div class="group-members">${mh}</div>`;
    gl.appendChild(div);
  }
  const rl=document.getElementById('rules-list');rl.innerHTML='';
  if(!rules.length)rl.innerHTML='<div class="empty-state empty-state-compact"><span class="empty-icon"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></span>No rules yet</div>';
  for(const r of rules){
    const div=document.createElement('div');div.className='rule-card';
    const ph=r.permissions.map(p=>'<span class="perm-badge">'+escapeHtml(p)+'</span>').join('');
    div.innerHTML='<div class="rule-info"><div class="rule-subject">'+(r.subject_type==='user'?'<svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>':'<svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>')+' '+escapeHtml(r.subject_id)+'</div><div class="rule-path">→ '+escapeHtml(r.path)+'</div><div class="rule-perms">'+ph+'</div></div><button class="btn btn-danger btn-sm" data-action="deleteRule" data-rule-id="'+Number(r.rule_id)+'">✕</button>';
    rl.appendChild(div);
  }
}
async function deleteRule(id){if(!confirm('Delete this rule?'))return;const resp=await api('DELETE','/permissions/rules/'+id);if(resp.ok){toast('Rule deleted','success');loadPerms()}else{const d=await resp.json();toast(d.detail,'error')}}
function showCreateGroupModal(){document.getElementById('group-name').value='';document.getElementById('group-home-path').value='';document.getElementById('group-home-auto').checked=false;document.getElementById('group-storage-max').value='';document.getElementById('group-storage-max-unit').value='GB';openModal('group-modal')}
async function doCreateGroup(){const name=document.getElementById('group-name').value.trim();if(!name)return;const homePath=document.getElementById('group-home-path').value.trim();const autoHome=document.getElementById('group-home-auto').checked;const storageMaxRaw=document.getElementById('group-storage-max').value.trim();const storageMaxUnit=document.getElementById('group-storage-max-unit').value;const payload={};if(homePath!=='')payload.home_path=homePath;payload.auto_generate_user_home=autoHome;const storageMaxBytes=parseStorageLimit(storageMaxRaw,storageMaxUnit);if(storageMaxBytes==='invalid'){toast('Storage max must be a non-negative number','error');return}if(storageMaxBytes!==null)payload.storage_max_bytes=storageMaxBytes;const resp=await api('POST','/permissions/groups/'+name,payload);if(resp.ok){toast('Group created','success');closeModal('group-modal');loadPerms()}else{const d=await resp.json();toast(d.detail,'error')}}
async function deleteGroup(name){if(!confirm('Delete group "'+name+'"?'))return;const resp=await api('DELETE','/permissions/groups/'+name);if(resp.ok){toast('Group deleted','success');loadPerms()}else{const d=await resp.json();toast(d.detail,'error')}}
async function showAddMemberModal(groupName){
  memberTargetGroup=groupName;document.getElementById('member-group-name').textContent=groupName;
  const sel=document.getElementById('member-username');sel.innerHTML='';
  if(!_cachedUsers.length){const r=await api('GET','/users/');if(r.ok)_cachedUsers=await r.json()}
  for(const u of _cachedUsers){const opt=document.createElement('option');opt.value=u.username;opt.textContent=u.username;sel.appendChild(opt)}
  openModal('member-modal');
}
async function doAddMember(){const username=document.getElementById('member-username').value;const resp=await api('POST','/permissions/groups/'+memberTargetGroup+'/members',{username});if(resp.ok){toast('Member added','success');closeModal('member-modal');loadPerms()}else{const d=await resp.json();toast(d.detail,'error')}}
async function removeMember(g,u){if(!confirm('Remove "'+u+'" from "'+g+'"?'))return;const resp=await api('DELETE','/permissions/groups/'+g+'/members/'+u);if(resp.ok){toast('Removed','success');loadPerms()}else{const d=await resp.json();toast(d.detail,'error')}}
async function showAddRuleModal(){
  if(!_cachedUsers.length){const r=await api('GET','/users/');if(r.ok)_cachedUsers=await r.json()}
  document.getElementById('rule-path').value='/';
  document.getElementById('rule-perms-checkboxes').innerHTML=ALL_PERMS.map(p=>'<label class="checkbox-label rule-checkbox"><input type="checkbox" name="perm" value="'+p+'"> '+p+'</label>').join('');
  refreshRuleSubjectOptions();openModal('rule-modal');
}
function refreshRuleSubjectOptions(){
  const type=document.getElementById('rule-subject-type').value;const sel=document.getElementById('rule-subject-id');sel.innerHTML='';
  const items=type==='user'?_cachedUsers.map(u=>u.username):_cachedGroups.map(g=>g.name);
  for(const item of items){const opt=document.createElement('option');opt.value=item;opt.textContent=item;sel.appendChild(opt)}
}
async function doAddRule(){
  const subject_type=document.getElementById('rule-subject-type').value;
  const subject_id=document.getElementById('rule-subject-id').value;
  const path=document.getElementById('rule-path').value.trim()||'/';
  const permissions=[...document.querySelectorAll('#rule-perms-checkboxes input[name=perm]:checked')].map(el=>el.value);
  if(!permissions.length){toast('Select at least one permission','error');return}
  const resp=await api('POST','/permissions/rules',{subject_type,subject_id,path,permissions});
  if(resp.ok){toast('Rule added','success');closeModal('rule-modal');loadPerms()}else{const d=await resp.json();toast(d.detail,'error')}
}

async function loadLogs(){
  const filter=document.getElementById('log-filter')?.value.trim();
  const url='/logs/?lines=300'+(filter?'&filter='+encodeURIComponent(filter):'');
  const resp=await api('GET',url);if(!resp.ok)return;
  const data=await resp.json();const lines=data.lines||[];
  const output=document.getElementById('log-output');const empty=document.getElementById('logs-empty');
  if(!lines.length){output.innerHTML='';show(empty);return}
  hide(empty);
  output.innerHTML=lines.map(line=>{
    let cls='';
    if(line.includes('AUTH_'))cls='log-auth';
    else if(line.includes('FILE_UPLOAD')||line.includes('FILE_WRITE')||line.includes('MKDIR'))cls='log-upload';
    else if(line.includes('FILE_DOWNLOAD')||line.includes('FILE_READ')||line.includes('SHARE_ACCESS'))cls='log-download';
    else if(line.includes('DELETE')||line.includes('QUOTA'))cls='log-delete';
    else if(line.includes('SHARE'))cls='log-share';
    else if(line.includes('USER_'))cls='log-user';
    else if(line.includes('PERM_DENIED')||line.includes('TOTP_FAILURE'))cls='log-warn';
    return'<div class="log-line '+cls+'">'+line.replace(/</g,'&lt;')+'</div>';
  }).join('');
  output.scrollTop=output.scrollHeight;
}

function openModal(id){document.getElementById(id).classList.remove('hidden')}
function closeModal(id){
  const modal=document.getElementById(id);
  modal.classList.add('hidden');
  if(id==='preview-modal'){
    modal.classList.remove('preview-fit');
    const area=document.getElementById('preview-area');
    if(area){
      area.classList.remove('preview-media-mode');
      area.innerHTML='';
    }
  }
}
document.querySelectorAll('.modal-overlay').forEach(o=>o.addEventListener('click',e=>{if(e.target===o)o.classList.add('hidden')}));
document.addEventListener('keydown',e=>{
  if(e.key==='Escape')document.querySelectorAll('.modal-overlay').forEach(m=>m.classList.add('hidden'));
  if(e.key==='Enter'&&!document.getElementById('login-screen').classList.contains('hidden')){
    if(!isHidden(document.getElementById('totp-form')))doTOTP();else doLogin();
  }
});

let toastTimer;
function toast(msg,type='info'){
  clearTimeout(toastTimer);
  let el=document.getElementById('toast-el');
  if(!el){el=document.createElement('div');el.id='toast-el';document.body.appendChild(el)}
  el.className='toast '+type;el.textContent=msg;
  toastTimer=setTimeout(()=>el.remove(),3500);
}


function dispatchDataAction(el, event){
  const action=el.dataset.action;
  if(!action)return false;
  const expectedEvent=el.dataset.event || 'click';
  if(event.type!==expectedEvent)return false;
  const arg1=el.dataset.arg1;
  const arg2=el.dataset.arg2;
  const path=el.dataset.path ?? arg1 ?? '';
  const username=el.dataset.username ?? arg1 ?? '';
  switch(action){
    case 'showPanel': showPanel(arg1); break;
    case 'doLogout': doLogout(); break;
    case 'reloadFiles': reloadFiles(); break;
    case 'setView': setView(arg1); break;
    case 'handleUpload': handleUpload(el.files); break;
    case 'showMkdirModal': showMkdirModal(); break;
    case 'toggleSort': toggleSort(arg1); break;
    case 'loadSettings': loadSettings(); break;
    case 'doChangeMyPassword': doChangeMyPassword(); break;
    case 'setupMyTOTP': setupMyTOTP(); break;
    case 'disableMyTOTP': disableMyTOTP(); break;
    case 'loadShares': loadShares(); break;
    case 'showCreateShareModal': showCreateShareModal(); break;
    case 'loadUsers': loadUsers(); break;
    case 'showCreateUserModal': showCreateUserModal(); break;
    case 'loadPerms': loadPerms(); break;
    case 'showCreateGroupModal': showCreateGroupModal(); break;
    case 'showAddRuleModal': showAddRuleModal(); break;
    case 'loadLogs': loadLogs(); break;
    case 'closeModal': closeModal(arg1); break;
    case 'doMkdir': doMkdir(); break;
    case 'doRename': doRename(); break;
    case 'doCreateShare': doCreateShare(); break;
    case 'doCreateUser': doCreateUser(); break;
    case 'doSetUserStorage': doSetUserStorage(); break;
    case 'doTOTPConfirm': doTOTPConfirm(); break;
    case 'refreshRuleSubjectOptions': refreshRuleSubjectOptions(); break;
    case 'doAddRule': doAddRule(); break;
    case 'doCreateGroup': doCreateGroup(); break;
    case 'doAddMember': doAddMember(); break;
    case 'doDeleteConfirm': doDeleteConfirm(); break;
    case 'navigateTo': navigateTo(path); break;
    case 'previewFile': previewFile(path, el.dataset.name ?? arg2 ?? path.split('/').pop()); break;
    case 'downloadFile': downloadFile(path); break;
    case 'promptShare': promptShare(path); break;
    case 'promptRename': promptRename(path); break;
    case 'showDeleteConfirm': showDeleteConfirm(path, el.dataset.isDir==='true' || arg2==='true'); break;
    case 'revokeShare': revokeShare(el.dataset.token ?? arg1); break;
    case 'copyText': copyText(el.dataset.text ?? arg1); break;
    case 'showSetUserStorageModal': {
      const raw=el.dataset.storageMax;
      const value=raw===''||raw===undefined?null:Number(raw);
      showSetUserStorageModal(username, value);
      break;
    }
    case 'toggleUser': toggleUser(username, el.dataset.enabled==='true' || arg2==='true'); break;
    case 'setupTOTP': setupTOTP(username); break;
    case 'disableTOTP': disableTOTP(username); break;
    case 'resetPwd': resetPwd(username); break;
    case 'deleteUser': deleteUser(username); break;
    case 'showAddMemberModal': showAddMemberModal(el.dataset.group ?? arg1); break;
    case 'deleteGroup': deleteGroup(el.dataset.group ?? arg1); break;
    case 'removeMember': removeMember(el.dataset.group ?? arg1, username); break;
    case 'deleteRule': deleteRule(Number(el.dataset.ruleId ?? arg1)); break;
    default: return false;
  }
  return true;
}

document.addEventListener('click', event=>{
  const el=event.target.closest('[data-action]');
  if(!el)return;
  if(dispatchDataAction(el,event)){
    event.preventDefault();
    event.stopPropagation();
  }
});

document.addEventListener('change', event=>{
  const el=event.target.closest('[data-action]');
  if(!el)return;
  if(dispatchDataAction(el,event)){
    event.preventDefault();
    event.stopPropagation();
  }
});

window.doLogin=doLogin;
window.doTOTP=doTOTP;
document.getElementById('login-btn')?.addEventListener('click',()=>doLogin());
document.getElementById('totp-btn')?.addEventListener('click',()=>doTOTP());

(async()=>{
  const ok=await tryRefresh();if(ok){await finishLogin();return}
  document.getElementById('login-user')?.focus();
})();
