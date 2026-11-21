import {uuid,isoNow,escapeHTML,readJSON,saveFile,sha256,canonicalJson,verifyObject,fingerprint,decryptJSON,calculateOutcome,computeReport,normalizeLegacyShare,normalizePmfShare,validateInquiry,isExpired,maybeNum} from './common.mjs';
const $=id=>document.getElementById(id);let received=[],listings=[];
const status=(msg,err=false)=>{$('status').textContent=msg;$('status').className=err?'error':'ok';};
const errStr=e=>e?.message||String(e);
async function getCatalog(){try{const r=await fetch('./data/listings.json',{cache:'no-store'});const d=await r.json();if(Array.isArray(d))listings=d;}catch{listings=[]}}
function buyerFields(){return {buyerId:$('buyerId').value.trim(),buyerName:$('buyerName').value.trim(),campaignId:$('campaignId').value.trim()}}
function findPackageId(id){return received.some(x=>x.packageId===id)}
async function handleRelease(x,pass,ctx){
 if(x.format!=='GARD_ELI_RELEASE_V1'||!x.packageId||!x.sender?.publicJwk||!x.cipher||!x.signature)throw Error('새 패키지 형식이 불완전합니다.');
 const unsigned={...x};delete unsigned.signature;
 if(!await verifyObject(unsigned,x.signature,x.sender.publicJwk))throw Error('ECDSA-P256 서명 검증 실패. 자료 사용 중지');
 if(await sha256(canonicalJson(x.cipher))!==x.cipherHash)throw Error('암호문 SHA-256 검증 실패');
 if(await fingerprint(x.sender.publicJwk)!==x.sender.fingerprint)throw Error('공개키 지문 불일치');
 if(x.recipient?.buyerId!==ctx.buyerId||x.recipient?.campaignId!==ctx.campaignId)throw Error('현재 구매자·캠페인과 수신대상이 일치하지 않습니다.');
 if(isExpired(x.terms?.usageExpiry)||isExpired(x.terms?.retentionUntil))throw Error('이용허락 또는 보유 기간이 만료되었습니다.');
 if(!pass)throw Error('암호화 자료를 열려면 별도 수령한 패키지 암호가 필요합니다.');
 const data=await decryptJSON(x.cipher,pass);
 if(data.format!=='GARD_ELI_APPROVED_DATA_V1'||data.buyerId!==ctx.buyerId||data.campaignId!==ctx.campaignId||data.listingId!==x.listingId||data.requestId!==x.requestId)throw Error('복호화 자료와 서명 봉투의 수신자/전시 ID가 일치하지 않습니다.');
 const listing=listings.find(z=>z.listingId===x.listingId);
 let pinned=false;
 if(listing&&listing.signature){const publicListing={...listing};delete publicListing.signature;
  pinned=(await verifyObject(publicListing,listing.signature,listing.ownerKey))&&(await fingerprint(listing.ownerKey))===x.sender.fingerprint;
 }
 if(!x.terms?.noAiTraining||!x.terms?.noOnwardSharing)throw Error('기본 제한이 누락된 패키지입니다.');
 return {...data,packageId:x.packageId,verification:pinned?'SIGNED_KEY_MATCHES_SHOWROOM':'SIGNED_SELF_ASSERTED_UNPINNED',sourceType:'GARD_ELI_RELEASE_V1',priceKrw:x.terms.priceKrw,usedFor:x.terms.purpose,retentionUntil:x.terms.retentionUntil,usageExpiry:x.terms.usageExpiry,terms:x.terms,receivedAt:isoNow()};
}
async function handleLegacy(x,ctx){
 if(x.format==='gardshare.json'){
  const p=await normalizePmfShare(x);
  if(p.campaignId!==ctx.campaignId||p.buyerId!==ctx.buyerId)throw Error('PMF 파일의 기관 tenantId 또는 캠페인이 현재 구매자와 다릅니다.');
  return p;
 }
 if(x.format==='GARD_ELI_SHARE_V1'){
  const p=await normalizeLegacyShare(x);
  if(p.campaignId!==ctx.campaignId||p.buyerId!==ctx.buyerId)throw Error('기존 제공 파일의 수신 기관 또는 캠페인이 일치하지 않습니다.');
  return {...p,legacyComparable:x.payloadJson?JSON.parse(x.payloadJson)?.items?.outcomes?.[0]?.comparability==='COMPARABLE':false,sourceType:'GARD_ELI_SHARE_V1',receivedAt:isoNow()};
 }
 if(x.format==='GARD_ELI_LISTING_V1')throw Error('이 파일은 오너의 전시용 .gardlisting.json입니다. 상단 공개 전시장에만 불러올 수 있고, 사회성과 수신 자료가 아닙니다.');
 if(x.format==='GARD_ELI_INQUIRY_V1')throw Error('이 파일은 구매자 협상 요청 JSON입니다. 오너의 승인 후 제공받은 .gardrelease.json을 선택하세요.');
 if(x.protocol==='ELI-P2P'&&x.package_type==='DISCLOSURE_SUBMISSION'){
  if((await sha256(canonicalJson(x.payload)))!==x.payload_hash)throw Error('ELI-P2P 원본 해시 검증 실패');
  if(x.recipient_node&&x.recipient_node!==ctx.buyerId)throw Error('다른 구매자에게 지정된 ELI-P2P 패키지입니다.');
  if(x.payload.call_id!==ctx.campaignId)throw Error('ELI-P2P call_id와 캠페인 ID가 일치하지 않습니다.');
  const a=x.payload.disclosed_outcomes?.[0];if(!a)throw Error('ELI-P2P 자료에서 공개된 outcome이 없습니다.');
  return {format:'GARD_ELI_APPROVED_DATA_V1',ownerRef:x.payload.participant_node_id||x.package_id,pseudonym:x.payload.participant_pseudonym||'익명',packageId:x.package_id,campaignId:ctx.campaignId,buyerId:ctx.buyerId,listingId:null,provider:'수신한 ELI-P2P 파일',service:'기존 공개 과업',task:a.title||'미확인 과업',metric:a.title||'원시 결과',unit:a.raw_unit||'unknown',direction:'UNKNOWN',baseline:maybeNum(a.raw_score_pre),followup:maybeNum(a.raw_score_post),sameTask:false,measurementStatus:a.measurement_status||'UNVERIFIED',attributionStatus:'NOT_VALIDATED_BY_THIS_APP',sourceType:'ELI-P2P',verification:'HASH_MATCHED_SIGNATURE_NOT_VERIFIED',receivedAt:isoNow(),legacyComparable:false,isDemo:!!x.payload.is_demo};
 }
 throw Error('지원하지 않는 패키지 형식입니다.');
}
async function importFiles(){try{const ctx=buyerFields();if(!ctx.buyerId||!ctx.campaignId)throw Error('구매자 ID와 캠페인 ID를 먼저 입력하세요.');const files=[...$('releaseFiles').files];if(!files.length)throw Error('오너 제공 파일을 선택하세요.');let imported=0;const errors=[];
 for(const file of files){try{const obj=await readJSON(file);const row=obj.format==='GARD_ELI_RELEASE_V1'?await handleRelease(obj,$('receivedPass').value,ctx):await handleLegacy(obj,ctx);
  if(findPackageId(row.packageId))throw Error('중복 패키지 ID: 재수입 차단');received.push(row);imported++;
 }catch(e){errors.push(`${file.name}: ${errStr(e)}`)}}
 $('receivedPass').value='';render();status(`수신 ${imported}건 성공 · ${errors.length}건 제외${errors.length?' — '+errors.join(' / '):''}`,errors.length>0);
}catch(e){status(errStr(e),true)}}
function render(){
 $('verificationRows').innerHTML=received.map(e=>{const r=calculateOutcome(e);return `<article class="item"><span class="chip">${escapeHTML(e.verification||e.securityLevel||'검증 미상')}</span><h3>${escapeHTML(e.pseudonym)}</h3><p>${escapeHTML(e.task)} · ${escapeHTML(e.metric)}</p><div class="metrics"><span class="metric">${escapeHTML(e.baseline??'결측')} → ${escapeHTML(e.followup??'결측')} ${escapeHTML(e.unit)}</span><span class="metric">${escapeHTML(r.interpretation)}</span></div><small>자료: ${escapeHTML(e.sourceType)} · ${escapeHTML(e.packageId)}</small>${e.sourceType!=='GARD_ELI_RELEASE_V1'?`<div><label for="legacy-${escapeHTML(e.packageId)}">기존 자료의 개선 방향 직접 확인</label><select data-direction-id="${escapeHTML(e.packageId)}"><option value="UNKNOWN" ${e.direction==='UNKNOWN'?'selected':''}>미확인 — 보고서 비교에서 제외</option><option value="INCREASE" ${e.direction==='INCREASE'?'selected':''}>수치 증가가 개선</option><option value="DECREASE" ${e.direction==='DECREASE'?'selected':''}>수치 감소가 개선</option></select><small>기존 파일의 동일 과업 확인 기록이 있으면 방향 선택 후에만 비교합니다.</small></div>`:''}</article>`}).join('')||'<div class="empty">수신한 자료가 없습니다. 패키지 암호와 정확한 기관/캠페인 ID를 확인하세요.</div>';
 $('feedbackPackage').innerHTML=received.map(x=>`<option value="${escapeHTML(x.packageId)}">${escapeHTML(x.pseudonym)} · ${escapeHTML(x.packageId.slice(0,15))}</option>`).join('')||'<option value="">대상 없음</option>';
 const report=computeReport(received,$('invited').value,$('campaignId').value.trim());
 let warnings=[];
 if(!report.denominatorOk)warnings.push('초대자 수는 수신한 고유 오너 수 이상인 0 이상의 정수여야 합니다. 분모가 검증되지 않아 해당 비율을 계산하지 않습니다.');
 if(report.duplicatePackages.length)warnings.push(`동일 오너의 추가 제공 ${report.duplicatePackages.length}건은 전역 분모 중복 방지를 위해 제외했습니다.`);
 if(report.INCONCLUSIVE)warnings.push(`${report.INCONCLUSIVE}건은 결측·단위·비교조건·기존 형식 정보 불충분으로 해석 보류입니다.`);
 if(received.some(x=>x.isDemo))warnings.push('가상 시연 자료가 포함되어 있습니다. 실제 사업성과 또는 수금 증거로 사용하지 마세요.');
 if(received.some(x=>x.verification==='SIGNED_SELF_ASSERTED_UNPINNED'))warnings.push('일부 서명 공개키는 승인된 전시장 목록과 일치 확인되지 않았습니다. 발신자의 실명·법적 지위는 인증되지 않았습니다.');
 if(received.some(x=>x.sourceType!=='GARD_ELI_RELEASE_V1'))warnings.push('기존 저장소에서 수신한 자료는 새 암호화·서명 프로토콜과 동일 수준으로 검증하지 않았습니다.');
 $('reportWarnings').innerHTML=warnings.map(x=>`<div class="notice">${escapeHTML(x)}</div>`).join('');
 const metrics=[['고유 오너 수',report.acceptedUniqueOwners+'명'],['비교 가능',report.comparable+'명'],['개선',report.IMPROVED+'명'],['유지',report.MAINTAINED+'명'],['악화',report.WORSENED+'명'],['해석 보류',report.INCONCLUSIVE+'명'],['비교 가능자 중 개선율',report.improvementAmongComparable===null?'계산 불가':report.improvementAmongComparable+'%'],['전체 초대 중 개선 확보 범위',report.improvementScopeAmongInvited===null?'계산 불가':report.improvementScopeAmongInvited+'%']];
 $('summary').innerHTML=metrics.map(([k,v])=>`<div class="summary-item"><strong>${escapeHTML(v)}</strong><small>${escapeHTML(k)}</small></div>`).join('');
 $('groupTable').innerHTML=report.groups.length?`<table class="simpletable"><thead><tr><th>동일 과업 / 지표 / 단위</th><th>비교 가능</th><th>전 평균</th><th>후 평균</th><th>평균 변화</th></tr></thead><tbody>${report.groups.map(g=>`<tr><td>${escapeHTML(g.key)}</td><td>${g.comparable}</td><td>${g.meanBaseline??'-'}</td><td>${g.meanFollowup??'-'}</td><td>${g.meanDelta??'-'}</td></tr>`).join('')}</tbody></table>`:'<p class="muted">계산할 자료가 없습니다.</p>';
 $('recordTable').innerHTML=report.rows.length?`<table class="simpletable"><thead><tr><th>오너(가명)</th><th>지표</th><th>사전</th><th>사후</th><th>판정</th><th>증거 등급</th></tr></thead><tbody>${report.rows.map(e=>`<tr><td>${escapeHTML(e.pseudonym)}</td><td>${escapeHTML(e.metric)}</td><td>${escapeHTML(e.baseline??'결측')}</td><td>${escapeHTML(e.followup??'결측')}</td><td>${escapeHTML(calculateOutcome(e).interpretation)}</td><td>${escapeHTML(e.verification||e.securityLevel||'미상')}</td></tr>`).join('')}</tbody></table>`:'<p class="muted">아직 수신된 개인 데이터가 없습니다.</p>';
}
$('verificationRows').addEventListener('change',e=>{const s=e.target.closest('select[data-direction-id]');if(!s)return;const x=received.find(q=>q.packageId===s.dataset.directionId);if(!x)return;x.direction=s.value;x.sameTask=x.legacyComparable===true&&s.value!=='UNKNOWN';x.reviewedDirectionAt=isoNow();render();status('기존 기록에 관해 구매자가 비교 방향을 지정했습니다. 이 작업은 독립 검증·승인이 아닙니다.');});
$('loadInquiry').addEventListener('click',async()=>{try{const j=await readJSON($('myInquiry').files[0]);if(j.format==='GARD_ELI_LISTING_V1')throw Error('선택한 파일은 오너 공개 전시용 JSON입니다. 위의 공개 전시장에서 사용하세요. 여기에는 GARD_ELI_INQUIRY_V1 구매자 요청 파일만 가져올 수 있습니다.');const q=validateInquiry(j);$('buyerId').value=q.buyerId;$('buyerName').value=q.buyerName;$('campaignId').value=q.campaignId;received=[];render();status('협상 요청에 기록된 구매자·캠페인 식별자를 가져왔습니다.');}catch(e){status(errStr(e),true)}});
$('importReleases').addEventListener('click',importFiles);
$('clearMemory').addEventListener('click',()=>{if(received.length&&!confirm('현재 열린 탭에 보유한 수신자료를 초기화하시겠습니까?'))return;received=[];render();status('메모리에서 수신자료를 초기화했습니다. 기존 파일 사본은 삭제하지 않았습니다.');});
for(const id of ['buyerId','campaignId','invited'])$(id).addEventListener('change',render);
$('exportReport').addEventListener('click',async()=>{try{const report=computeReport(received,$('invited').value,$('campaignId').value.trim());if(!report.rows.length)throw Error('보고서에 수신 자료가 없습니다.');const out={format:'GARD_ELI_BUYER_REPORT_V1',reportId:`REP-${uuid()}`,buyer:buyerFields(),generatedAt:isoNow(),method:'RAW_ONLY_DESCRIPTIVE_COUNTS',report:{...report,groups:report.groups.map(({rows,...g})=>g)},interpretation:'개인 변화 기술통계; 사회성과의 인과적 귀속과 화폐가치 평가 미수행',isDemo:received.some(x=>x.isDemo)};out.reportHash=await sha256(canonicalJson(out));saveFile(`GARD_ELI_REPORT_${out.reportId}.json`,out);status('측정 결과 JSON 저장 완료. 가명별 원장도 포함되어 있으므로 외부 재공개에 주의하세요.');}catch(e){status(errStr(e),true)}});
$('exportCsv').addEventListener('click',()=>{try{const r=computeReport(received,$('invited').value,$('campaignId').value.trim());if(!r.rows.length)throw Error('내보낼 행이 없습니다.');const cols=['packageId','pseudonym','provider','service','task','metric','unit','direction','baseline','followup','measurementSource','baselineSource','verification','interpretation'];const quote=v=>'"'+String(v??'').replace(/^[=+@\-\t\r]/,s=>"'"+s).replace(/"/g,'""')+'"';const text='\uFEFF'+[cols.join(','),...r.rows.map(e=>cols.map(c=>quote(c==='interpretation'?calculateOutcome(e).interpretation:e[c])).join(','))].join('\r\n');const blob=new Blob([text],{type:'text/csv;charset=utf-8'});const u=URL.createObjectURL(blob),a=document.createElement('a');a.href=u;a.download='GARD_ELI_accepted_rows.csv';document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(u),5000);status('CSV 저장 완료. 비식별 정보라도 재식별 위험을 점검하세요.');}catch(e){status(errStr(e),true)}});
$('exportReturn').addEventListener('click',()=>{try{const e=received.find(x=>x.packageId===$('feedbackPackage').value);if(!e)throw Error('회신 대상 자료를 선택하세요.');const ctx=buyerFields();if(!ctx.buyerId)throw Error('구매자 ID가 없습니다.');const o={format:'GARD_ELI_RETURN_V1',returnId:`RET-${uuid()}`,packageId:e.packageId,buyerId:ctx.buyerId,buyerName:ctx.buyerName,campaignId:ctx.campaignId,reviewStatus:$('reviewStatus').value,staffObservation:$('staffObservation').value.trim(),improvementPromise:$('improvementPromise').value.trim(),originAuthentication:'NOT_CRYPTOGRAPHICALLY_SIGNED',createdAt:isoNow()};if(!o.staffObservation||!o.improvementPromise)throw Error('검토 의견과 개선 약속을 작성하세요.');saveFile(`GARD_RETURN_${o.returnId}.gardreturn.json`,o);status('오너에게 반환할 회신 JSON을 생성했습니다. 별도 안전한 채널로 전달하세요.');}catch(err){status(errStr(err),true)}});
getCatalog().then(()=>{render();status('구매자 앱 준비 완료. 파일은 자동 수신되지 않습니다.');});
