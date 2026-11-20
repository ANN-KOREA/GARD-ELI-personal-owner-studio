/* GARD ELI Owner-to-Buyer Impact Market v1.0 - independent, browser-only core.
   Methodology mapped from ANN-KOREA/GARD-ELI-, GARD-ELI-PMF, GARD-ELI-MARKET,
   and ELI-P2P-Impact-Exchange-. No private repository contents embedded. */
export const VERSION = '1.0.0';
export const VAULT_KEY = 'gard.eli.impact.owner.v1.encrypted';
export const KDF_ITERATIONS = 600000;
export const MAX_INPUT_BYTES = 1024 * 1024;
export const DEMO_PREFIX = 'DEMO-';
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export const uuid = () => crypto.randomUUID();
export const isoNow = () => new Date().toISOString();
export const escapeHTML = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export const formatKRW = n => Number.isFinite(Number(n)) ? Number(n).toLocaleString('ko-KR') + '원' : '미정';
export function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(k => [k, canonical(value[k])]));
  return value;
}
export const canonicalJson = value => JSON.stringify(canonical(value));
export const b64 = arr => { let s=''; const a=new Uint8Array(arr); for(let i=0;i<a.length;i+=0x8000)s+=String.fromCharCode(...a.subarray(i,i+0x8000));return btoa(s);};
export const fromB64 = str => Uint8Array.from(atob(str), c => c.charCodeAt(0));
export async function sha256(value) { const bytes = typeof value === 'string' ? textEncoder.encode(value) : value; return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))).map(x=>x.toString(16).padStart(2,'0')).join(''); }
async function derive(pass, salt, iters) {
  const material = await crypto.subtle.importKey('raw', textEncoder.encode(pass), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2', salt, iterations:iters, hash:'SHA-256'}, material, {name:'AES-GCM',length:256}, false, ['encrypt','decrypt']);
}
export async function encryptJSON(value, pass) {
  if (String(pass).length < 12) throw new Error('암호는 12자 이상 입력해야 합니다.');
  const salt=crypto.getRandomValues(new Uint8Array(16)), iv=crypto.getRandomValues(new Uint8Array(12));
  const key=await derive(pass,salt,KDF_ITERATIONS);
  const ciphertext=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,textEncoder.encode(JSON.stringify(value)));
  return {alg:'AES-256-GCM',kdf:'PBKDF2-SHA256',iterations:KDF_ITERATIONS,salt:b64(salt),iv:b64(iv),ciphertext:b64(ciphertext)};
}
export async function decryptJSON(envelope,pass) {
  if(!envelope || envelope.alg!=='AES-256-GCM'||envelope.kdf!=='PBKDF2-SHA256'||envelope.iterations!==KDF_ITERATIONS)throw new Error('지원하지 않는 암호화 봉투 형식입니다.');
  if(!envelope.salt||!envelope.iv||!envelope.ciphertext)throw new Error('암호화 데이터가 불완전합니다.');
  const salt=fromB64(envelope.salt), iv=fromB64(envelope.iv), cipher=fromB64(envelope.ciphertext);
  if(salt.length!==16||iv.length!==12||cipher.length<17)throw new Error('암호화 데이터 길이가 잘못되었습니다.');
  const key=await derive(pass,salt,envelope.iterations);
  try {const raw=await crypto.subtle.decrypt({name:'AES-GCM',iv},key,cipher);return JSON.parse(textDecoder.decode(raw));}
  catch {throw new Error('암호가 틀리거나 파일이 변경되었습니다.');}
}
export async function makeIdentity() {
  const k=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
  const publicJwk=await crypto.subtle.exportKey('jwk',k.publicKey);
  const privateJwk=await crypto.subtle.exportKey('jwk',k.privateKey);
  return {publicJwk,privateJwk,fingerprint:await sha256(canonicalJson(publicJwk))};
}
export async function signObject(value,privateJwk) {
  const key=await crypto.subtle.importKey('jwk',privateJwk,{name:'ECDSA',namedCurve:'P-256'},false,['sign']);
  return b64(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key,textEncoder.encode(canonicalJson(value))));
}
export async function verifyObject(value,signature,publicJwk){
  try{const key=await crypto.subtle.importKey('jwk',publicJwk,{name:'ECDSA',namedCurve:'P-256'},false,['verify']);return await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},key,fromB64(signature),textEncoder.encode(canonicalJson(value)));}
  catch{return false;}
}
export async function fingerprint(key){return sha256(canonicalJson(key));}
export function saveFile(name, obj) {
  const blob=new Blob([typeof obj==='string'?obj:JSON.stringify(obj,null,2)],{type:'application/json;charset=utf-8'});
  const url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=name;document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),5000);
}
export async function readJSON(file) {
  if(!file)throw new Error('JSON 파일을 선택하세요.');
  if(file.size>MAX_INPUT_BYTES)throw new Error('JSON 파일은 1 MiB 이하만 가져올 수 있습니다.');
  try{return JSON.parse(await file.text());}catch{throw new Error('유효한 UTF-8 JSON 파일이 아닙니다.');}
}
export function maybeNum(x) {if(x===null||x===undefined||String(x).trim()==='')return null;const n=Number(x);return Number.isFinite(n)?n:null;}
export function calculateOutcome(e){
  const b=maybeNum(e.baseline), f=maybeNum(e.followup);
  if(b===null||f===null)return {comparable:false,delta:null,interpretation:'INCONCLUSIVE',reason:'측정값 결측'};
  if(!e.sameTask)return {comparable:false,delta:null,interpretation:'INCONCLUSIVE',reason:'동일 과업·단위 검증 없음'};
  if(!['INCREASE','DECREASE'].includes(e.direction)||!String(e.unit||'').trim()||!String(e.metric||'').trim())return {comparable:false,delta:null,interpretation:'INCONCLUSIVE',reason:'측정지표·방향·단위 미설정'};
  const delta=Number((f-b).toFixed(6));
  const sign=e.direction==='INCREASE'?delta:-delta;
  return {comparable:true,delta,relativeChange:b===0?null:Number(((f-b)/Math.abs(b)*100).toFixed(2)),interpretation:sign>0?'IMPROVED':sign<0?'WORSENED':'MAINTAINED',reason:''};
}
export const validDate = s => /^\d{4}-\d{2}-\d{2}$/.test(String(s||'')) && !Number.isNaN(Date.parse(s));
export const isExpired = s => validDate(s) && s < new Date().toISOString().slice(0,10);
export function sanitizeListing(episode, owner){
  return {format:'GARD_ELI_LISTING_V1',listingId:episode.listingId,ownerAlias:owner.pseudonym,
    ownerKey:owner.keys.publicJwk,ownerKeyFingerprint:owner.keys.fingerprint,
    title:String(episode.publicTitle||'').slice(0,150),summary:String(episode.publicSummary||'').slice(0,1200),
    provider:String(episode.provider||'').slice(0,150),service:String(episode.service||'').slice(0,150),
    task:String(episode.task||'').slice(0,150),metric:String(episode.metric||'').slice(0,100),unit:String(episode.unit||'').slice(0,30),
    measurementStatus:'RAW_ONLY',disclosure:'INQUIRY_REQUIRED',isDemo:!!episode.isDemo,
    publishedAt:isoNow()};
}
export function validateInquiry(obj){
  if(!obj||obj.format!=='GARD_ELI_INQUIRY_V1'||!obj.listingId||!obj.buyerId||!obj.buyerName||!obj.purpose||!obj.campaignId) throw new Error('협상 요청 JSON 필수 항목이 없습니다.');
  if(String(obj.purpose).length>2000)throw new Error('이용 목적이 너무 깁니다.');
  return obj;
}
export function computeReport(entries,invited,campaignId){
  const scope=entries.filter(e=>String(e.campaignId)===String(campaignId));
  const byOwner=new Map();const duplicates=[];
  for(const e of scope){const id=String(e.ownerRef||e.pseudonym||e.packageId);if(byOwner.has(id)){duplicates.push(e.packageId);continue;}byOwner.set(id,e);}
  const rows=[...byOwner.values()];const count={IMPROVED:0,MAINTAINED:0,WORSENED:0,INCONCLUSIVE:0};
  for(const e of rows){const r=calculateOutcome(e);count[r.interpretation]++;}
  const comparable=count.IMPROVED+count.MAINTAINED+count.WORSENED;
  const n=Number(invited);
  const denominatorOk=Number.isSafeInteger(n)&&n>=rows.length&&n>=0;
  const groups={};
  for(const e of rows){const key=[e.task,e.metric,e.unit,e.direction].map(x=>String(x??'')).join(' | ');if(!groups[key])groups[key]={key,rows:[],comparable:0,improved:0,meanBaseline:null,meanFollowup:null,meanDelta:null};const r=calculateOutcome(e);groups[key].rows.push(e);if(r.comparable){groups[key].comparable++;if(r.interpretation==='IMPROVED')groups[key].improved++;}}
  for(const g of Object.values(groups)){const v=g.rows.filter(x=>calculateOutcome(x).comparable);if(v.length){g.meanBaseline=+(v.reduce((s,x)=>s+Number(x.baseline),0)/v.length).toFixed(3);g.meanFollowup=+(v.reduce((s,x)=>s+Number(x.followup),0)/v.length).toFixed(3);g.meanDelta=+(v.reduce((s,x)=>s+calculateOutcome(x).delta,0)/v.length).toFixed(3);}}
  return {campaignId,invited:denominatorOk?n:null,invitationEvidence:'BUYER_ENTERED_UNVERIFIED',acceptedUniqueOwners:rows.length,comparable,unreceived:denominatorOk?n-rows.length:null,...count,
    responseRate:denominatorOk&&n>0?+(rows.length/n*100).toFixed(2):null,
    improvementAmongComparable:comparable>0?+(count.IMPROVED/comparable*100).toFixed(2):null,
    improvementScopeAmongInvited:denominatorOk&&n>0?+(count.IMPROVED/n*100).toFixed(2):null,
    groups:Object.values(groups),rows,duplicatePackages:duplicates,denominatorOk,
    caveat:'선택 제공된 자기보고·관찰 기록의 기술통계. 개선 확보 범위는 효과 크기 아님. 원인 귀속, 사회가치 화폐화, Rasch 보정은 수행되지 않음.'};
}
export async function normalizeLegacyShare(envelope){
  if(envelope?.format!=='GARD_ELI_SHARE_V1'||typeof envelope.payloadJson!=='string'||!envelope.sha256)throw new Error('GARD_ELI_SHARE_V1 형식이 아닙니다.');
  if((await sha256(envelope.payloadJson))!==envelope.sha256)throw new Error('기존 제공파일 SHA-256 검증 실패');
  const p=JSON.parse(envelope.payloadJson);
  if(!p.items?.outcomes?.length)throw new Error('기존 패키지에 outcomes가 없습니다.');
  const o=p.items.outcomes[0];
  const row={format:'GARD_ELI_APPROVED_DATA_V1',ownerRef:`LEGACY-${p.subjectPseudonym||p.packageId}`,pseudonym:p.subjectPseudonym||'익명',packageId:envelope.packageId,
    campaignId:p.campaignRef?.campaignId||'LEGACY',buyerId:p.recipient?.recipientId||'',provider:'미상',service:'기존 제공 결과',
    task:o.metricName||'기존 과업',metric:o.metricName||'',unit:o.unit||'',direction:'INCREASE',baseline:o.baselineValue,followup:o.followupValue,
    sameTask:o.comparability==='COMPARABLE',measurementSource:'LEGACY_SHARE',baselineSource:'UNKNOWN',attribution:p.items.attribution?.statement||'',note:p.items.publicNoteForProvider||'',
    legacyInterpretation:o.interpretation,securityLevel:'HASH_ONLY_NO_SIGNATURE',verifiedAt:isoNow(),isDemo:!!p.isDemo};
  // Legacy interpretation direction cannot safely be inferred from a metric name.
  // Preserve original interpretation but do NOT recompute with an invented direction.
  row.direction='UNKNOWN';row.sameTask=false;
  return row;
}
export async function normalizePmfShare(envelope){
  if(envelope?.format!=='gardshare.json'||envelope.schemaVersion!=='2.0.0'||typeof envelope.payloadJson!=='string'||!envelope.payloadSha256)throw new Error('GARD ELI PMF 2.0 선택 제공 형식이 아닙니다.');
  if((await sha256(envelope.payloadJson))!==envelope.payloadSha256)throw new Error('GARD ELI PMF 제공파일 SHA-256 검증 실패');
  if(envelope.approval?.signerConfirmation!==true)throw new Error('PMF 제공파일에 당사자 제공 승인 표시가 없습니다.');
  const p=JSON.parse(envelope.payloadJson);const m=p.metrics?.[0];if(!m)throw new Error('PMF 제공파일에 측정지표가 없습니다.');
  return {format:'GARD_ELI_APPROVED_DATA_V1',ownerRef:`PMF-${envelope.responseRef||envelope.packageId}`,pseudonym:envelope.responseRef||'익명',packageId:envelope.packageId,
    campaignId:envelope.campaignId,buyerId:envelope.tenantId,provider:'기관 PMF 제공 데이터',service:'기존 고객 변화 측정',
    task:m.taskName||'미기재 과업',metric:m.metricId||'',unit:m.unit||'',direction:'UNKNOWN',baseline:m.baseline?.value??null,followup:m.followUp?.value??null,
    sameTask:false,legacyComparable:!!m.taskName&&!!m.unit&&m.baseline?.value!==null&&m.baseline?.value!==undefined&&m.followUp?.value!==null&&m.followUp?.value!==undefined,
    measurementSource:'LEGACY_PMF',baselineSource:m.baseline?.preRecordType||'UNKNOWN',attribution:(p.attributions||[]).map(x=>x.explanation).filter(Boolean).join(' / '),
    note:p.userStatement||'',legacyInterpretation:m.interpretation||'INCONCLUSIVE',securityLevel:'HASH_ONLY_NO_SIGNATURE',verification:'HASH_MATCHED_LEGACY_PMF',
    sourceType:'GARD_ELI_PMF_V2',isDemo:!!envelope.isDemo,receivedAt:isoNow()};
}
