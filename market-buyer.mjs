import {uuid,isoNow,escapeHTML,readJSON,saveFile,formatKRW,validateInquiry,verifyObject,fingerprint} from './common.mjs';
const $=id=>document.getElementById(id);
const state={list:[],temp:new Set()};
const err=e=>e?.message||String(e);
function status(text,error=false){$('mkStatus').textContent=text;$('mkStatus').style.color=error?'#991b1b':'#23645a';}
async function verifyListing(x){
 if(!x||x.format!=='GARD_ELI_LISTING_V1'||!x.listingId||!x.ownerKey||!x.signature||!x.ownerKeyFingerprint)throw Error('GARD_ELI_LISTING_V1 공개용 형식이 아닙니다.');
 const payload={...x};delete payload.signature;
 if(!(await verifyObject(payload,x.signature,x.ownerKey)))throw Error('공개용 JSON의 ECDSA 전자서명이 유효하지 않습니다.');
 if(await fingerprint(x.ownerKey)!==x.ownerKeyFingerprint)throw Error('공개용 JSON 공개키 지문이 일치하지 않습니다.');
 return x;
}
function draw(){
 const q=$('mkSearch').value.trim().toLowerCase(),kind=$('mkKind').value;
 const matched=state.list.filter(x=>(kind==='ALL'||(kind==='DEMO' ? !!x.isDemo : !x.isDemo))&&[x.title,x.summary,x.provider,x.service,x.metric,x.ownerAlias].join(' ').toLowerCase().includes(q));
 $('mkCount').textContent=`${matched.length}건`;
 $('mkList').innerHTML=matched.map(x=>`<article class="item"><span class="badge">${state.temp.has(x.listingId)?'서명 확인 · 임시 미리보기':x.isDemo?'합성 시연 · 실거래 아님':'서명 확인 · 오너 공개 요약'}</span><h3>${escapeHTML(x.title)}</h3><p>${escapeHTML(x.summary)}</p><p><strong>서비스 제공처</strong>: ${escapeHTML(x.provider)} · ${escapeHTML(x.service)}</p><p><strong>기록 대상</strong>: ${escapeHTML(x.task)}</p><p><strong>변화 지표</strong>: ${escapeHTML(x.metric)} (${escapeHTML(x.unit)})</p><p class="muted">오너 가명 ${escapeHTML(x.ownerAlias)} · 미공개 자료 접근 불가</p><button type="button" data-pick="${escapeHTML(x.listingId)}" class="secondary">이 사례에 협상 요청</button></article>`).join('')||'<div class="empty">조건에 맞는 공개 자료가 없습니다. 서명된 .gardlisting.json을 임시로 불러오거나 GitHub의 data/listings.json을 확인하세요.</div>';
 const selected=$('mkListing').value;
 $('mkListing').innerHTML=state.list.map(x=>`<option value="${escapeHTML(x.listingId)}">${escapeHTML(x.title)} ${state.temp.has(x.listingId)?'[임시]':x.isDemo?'[가상]':''}</option>`).join('')||'<option value="">선택 가능한 공개용 파일 없음</option>';
 if(state.list.some(x=>x.listingId===selected))$('mkListing').value=selected;
 $('mkDownload').disabled=state.list.length===0;
}
async function loadPublished(){
 try{const r=await fetch('./data/listings.json',{cache:'no-store'});if(!r.ok)throw Error(`HTTP ${r.status}`);
 const data=await r.json();if(!Array.isArray(data))throw Error('data/listings.json은 JSON 배열이어야 합니다.');
 const valid=[],errors=[];
 for(const x of data){try{valid.push(await verifyListing(x))}catch(e){errors.push(err(e))}}
 state.list=valid;draw();status(`서명 검증에 통과한 공개 사례 ${valid.length}건 · 검증 제외 ${errors.length}건${errors.length?' — '+errors.join('; '):''}`,!!errors.length);
 }catch(e){draw();status('GitHub에서 등록한 공개 목록을 읽지 못했습니다: '+err(e),true)}
}
$('mkSearch').addEventListener('input',draw);$('mkKind').addEventListener('change',draw);
$('mkList').addEventListener('click',e=>{const b=e.target.closest('button[data-pick]');if(!b)return;$('mkListing').value=b.dataset.pick;location.hash='buyerInquiry';$('mkBuyerName').focus()});
$('mkImportListing').addEventListener('click',async()=>{try{
 const x=await verifyListing(await readJSON($('mkListingFile').files[0]));
 const existing=state.list.findIndex(y=>y.listingId===x.listingId);
 if(existing>=0&&!state.temp.has(x.listingId))throw Error('이미 정식 전시장 목록에 등록된 공개용 파일입니다. 파일 가져오기는 필요하지 않습니다.');
 if(existing>=0)state.list[existing]=x;else state.list.unshift(x);
 state.temp.add(x.listingId);draw();$('mkListing').value=x.listingId;
 status('전자서명과 공개키 지문을 검증했습니다. 이 파일은 현재 브라우저에서만 보이는 임시 미리보기입니다.');location.hash='buyerInquiry';
 }catch(e){status(err(e),true)}});
$('mkInquiryForm').addEventListener('submit',e=>{e.preventDefault();try{
 const listing=state.list.find(x=>x.listingId===$('mkListing').value);
 if(!listing)throw Error('먼저 공개 전시 목록에서 오너 사례를 선택하세요.');
 const price=Number($('mkPrice').value);
 if(!Number.isSafeInteger(price)||price<0)throw Error('제안 금액은 0 이상의 정수여야 합니다.');
 const f=$('mkFields').value;
 const fields=f==='OUTCOME_PF_EF'?['OUTCOME','PF','EF']:f==='OUTCOME_EVIDENCE'?['OUTCOME','EVIDENCE']:f==='QUALITATIVE'?['OUTCOME','PF','EF','NARRATIVE']:['OUTCOME'];
 const request=validateInquiry({format:'GARD_ELI_INQUIRY_V1',version:'1.0.0',requestId:`INQ-${uuid()}`,
 listingId:listing.listingId,buyerId:$('mkBuyerId').value.trim(),buyerName:$('mkBuyerName').value.trim(),campaignId:$('mkCampaignId').value.trim(),purpose:$('mkPurpose').value.trim(),offeredPrice:price,currency:'KRW',requestedFields:fields,buyerContact:$('mkBuyerContact').value.trim(),createdAt:isoNow(),isDemo:!!listing.isDemo,status:'OFFER_ONLY_NO_CONTRACT'});
 saveFile(`GARD_INQUIRY_${request.requestId}.gard-inquiry.json`,request);
 // Mirror into buyer verification workspace so users don't need to retype fields.
 for(const [source,target] of [['mkBuyerId','buyerId'],['mkBuyerName','buyerName'],['mkCampaignId','campaignId']]){const t=$(target);if(t){t.value=$(source).value;t.dispatchEvent(new Event('change',{bubbles:true}))}}
 $('mkRequestStatus').textContent=`요청 JSON 저장 완료. 제안액 ${formatKRW(price)}은 계약·대금 지급이 아닙니다. 오너에게 별도 채널로 전달하세요.`;
 }catch(e){$('mkRequestStatus').textContent='저장 실패: '+err(e)}});
await loadPublished();
