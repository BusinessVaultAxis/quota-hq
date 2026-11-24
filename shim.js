// Runs the Quota HQ page against the Quota server instead of claude.ai.
(function(){
  const subs={},state={data:null};let timer=null;
  const api=async(method,url,body)=>{const r=await fetch(url,{method,credentials:"same-origin",headers:body!==undefined?{"Content-Type":"application/json"}:{},body:body!==undefined?JSON.stringify(body):undefined});
    if(r.status===401){location.href="/login";throw new Error("signed out")}const j=await r.json().catch(()=>({}));if(!r.ok){const e=new Error(j.error||"Request failed");e.code=r.status;throw e}return j};
  const snap=c=>({docs:((state.data&&state.data[c])||[]).map(d=>({id:d.id,data:()=>{const o=Object.assign({},d);delete o.id;return o}}))});
  const emit=()=>{for(const c in subs)subs[c].forEach(cb=>{try{cb(snap(c))}catch(e){console.error(e)}})};
  let last="";
  async function load(force){try{const nd=await api("GET","/api/data"),sig=JSON.stringify(nd);if(!force&&sig===last&&state.data)return;last=sig;state.data=nd;window.QHQ.me=state.data._me;window.QHQ.pre=!!state.data._pre;window.QHQ.repGoals=state.data._repGoals||null;if(state.data._me.role==="admin")await Promise.all([window.QHQ.loadApplicants(),window.QHQ.loadUsers()]);emit()}catch(e){console.error(e)}}
  const after=async r=>{await load(true);return r};
  const col=c=>({
    onSnapshot(cb){(subs[c]=subs[c]||[]).push(cb);if(state.data)setTimeout(()=>cb(snap(c)),0);return()=>{subs[c]=subs[c].filter(x=>x!==cb)}},
    add:data=>api("POST","/api/doc/"+c,data).then(r=>after({id:r.id})),
    doc:id=>({
      set:data=>c==="claims"?Promise.resolve():api("PUT","/api/doc/"+c+"/"+encodeURIComponent(id),data).then(after),
      update:data=>c==="claims"?Promise.resolve():api("PATCH","/api/doc/"+c+"/"+encodeURIComponent(id),data).then(after),
      delete:()=>c==="claims"?Promise.resolve():api("DELETE","/api/doc/"+c+"/"+encodeURIComponent(id)).then(after),
      get:async()=>{const d=((state.data&&state.data[c])||[]).find(x=>x.id===id);return{exists:!!d,data:()=>d}}
    })});
  const db={collection:col,doc:p=>{
    if(/^data\/users\/[^/]+\/prefs$/.test(p))return{get:async()=>{if(!state.data)await load();const pr=(state.data&&state.data._me.prefs)||{};return{exists:true,data:()=>pr}},set:d=>api("PUT","/api/prefs",d).then(after)};
    const [c,id]=p.split("/");return col(c).doc(id)}};
  const user={canEdit:async()=>{if(!state.data)await load();return !!(state.data&&state.data._me.role==="admin")},isOwner:async()=>false,can:async()=>null,
    me:async()=>{if(!state.data)await load();const m=state.data._me;return{id:m.id,email:m.email,name:"",isOwner:false}}};
  const downloads={save:async({filename,data})=>{const b=data instanceof Blob?data:new Blob([data],{type:filename.endsWith(".csv")?"text/csv":"text/html"});const a=document.createElement("a");a.href=URL.createObjectURL(b);a.download=filename;document.body.appendChild(a);a.click();setTimeout(()=>{URL.revokeObjectURL(a.href);a.remove()},500);return{status:"saved"}}};
  window.QHQ={me:null,pre:false,api,reload:load,users:[],
    loadUsers:async()=>{try{window.QHQ.users=await api("GET","/api/users")}catch(e){window.QHQ.users=[]}return window.QHQ.users},
    invite:(repId,email)=>api("POST","/api/users/invite",{repId,email}),
    revoke:id=>api("DELETE","/api/users/"+id),
    logout:()=>api("POST","/api/logout",{}).then(()=>{location.href="/login"}),
    applicants:[],recruitLink:()=>api("GET","/api/recruit-link"),
    loadApplicants:async()=>{try{window.QHQ.applicants=await api("GET","/api/applicants")}catch(e){window.QHQ.applicants=[]}return window.QHQ.applicants},
    approve:(id,scale)=>api("POST","/api/applicants/"+id+"/approve",{scale}).then(async r=>{await load();await window.QHQ.loadApplicants();return r}),
    decline:id=>api("DELETE","/api/applicants/"+id).then(()=>window.QHQ.loadApplicants())};
  window.claude={use:async n=>n==="db"?db:n==="user"?user:n==="downloads"?downloads:null};
  load().then(()=>{timer=setInterval(()=>{if(!document.hidden)load()},30000)});
  document.addEventListener("visibilitychange",()=>{if(!document.hidden)load()});
})();
