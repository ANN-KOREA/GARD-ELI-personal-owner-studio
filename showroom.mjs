import {uuid,isoNow,escapeHTML,saveFile,formatKRW,validateInquiry,verifyObject,fingerprint} from './common.mjs';
const $=id=>document.getElementById(id);let listings=[];
function setStatus(msg,err=false){$('status').textContent=msg;$('status').className=err?'error':'ok';}
function draw(){const q=$('search').value.toLowerCase(),kind=$('filterDemo').value;const filtered=listings.filter(x=>(kind==='ALL'||(kind==='DEMO')===!!x.isDemo)&&[x.title,x.provider,x.service,x.summary,x.ownerAlias].join(' ').toLowerCase().includes(q));
  $('listingCount').textContent=`${filtered.length}건`;
  $('listings').innerHTML=filtered.map(x=>`<article class="item"><span class="badge">${x.isDemo?'합성 시연 · 실거래 불가':'오너 승인 공개 목록'}</span><h3>${escapeHTML(x.title)}</h3><p>${escapeHTML(x.summary)}</p><p><strong>제공 기관</strong> ${escapeHTML(x.provider)} / ${escapeHTML(x.service)}</p><p><strong>변화 지표</strong> ${escapeHTML(x.metric)} (${escapeHTML(x.unit)})</p><p class="muted">오너: ${escapeHTML(x.ownerAlias)} · <strong>개인 원본은 공개되지 않음</strong></p><button class="secondary" data-listing="${escapeHTML(x.listingId)}">이 사례에 협상 요청</button></article>`).join('')||'<div class="empty">조건에 맞는 공개 목록이 없습니다. 오너가 승인한 JSON을 등록하면 나타납니다.</div>';
 $('selectedListing').innerHTML=listings.map(x=>`<option value="${escapeHTML(x.listingId)}">${escapeHTML(x.title)} ${x.isDemo?'[가상]':''}</option>`).join('')||'<option value="">공개 목록 없음</option>';
}
async function load(){try{const res=await fetch('./data/listings.json',{cache:'no-store'});if(!res.ok)throw new Error(`HTTP ${res.status}`);const arr=await res.json();if(!Array.isArray(arr))throw new Error('목록 JSON은 배열이어야 합니다.');const approved=[];let invalid=0;
 for(const x of arr){if(x?.format!=='GARD_ELI_LISTING_V1'||!x.listingId||!x.ownerKey||!x.signature){invalid++;continue;}
  const check={...x};delete check.signature;
  if(await verifyObject(check,x.signature,x.ownerKey)&&(await fingerprint(x.ownerKey))===x.ownerKeyFingerprint)approved.push(x);else invalid++;
 }
 listings=approved;
 draw();setStatus(`서명 검증된 전시 목록 ${listings.length}건 로딩 완료${invalid?' · 서명/형식 이상 '+invalid+'건 제외':''}. 실제 구매·승인 과정은 오너와 별도 진행합니다.`,invalid>0);}catch(e){setStatus(`전시장 데이터를 불러오지 못했습니다: ${e.message}`,true)}}
$('search').addEventListener('input',draw);$('filterDemo').addEventListener('change',draw);
$('listings').addEventListener('click',e=>{const btn=e.target.closest('button[data-listing]');if(btn){$('selectedListing').value=btn.dataset.listing;window.location.hash='inquiry';$('buyerName').focus();}});
$('inquiryForm').addEventListener('submit',e=>{e.preventDefault();try{const listing=listings.find(x=>x.listingId===$('selectedListing').value);if(!listing)throw Error('공개 목록을 선택하세요.');const price=Number($('offeredPrice').value);if(!Number.isSafeInteger(price)||price<0)throw Error('금액은 0 이상의 정수여야 합니다.');const fld=$('requestedFields').value;
const fields=fld==='OUTCOME_PF_EF'?['OUTCOME','PF','EF']:fld==='OUTCOME_EVIDENCE'?['OUTCOME','EVIDENCE']:fld==='QUALITATIVE'?['OUTCOME','PF','EF','NARRATIVE']:['OUTCOME'];
const request=validateInquiry({format:'GARD_ELI_INQUIRY_V1',version:'1.0.0',requestId:`INQ-${uuid()}`,listingId:listing.listingId,buyerId:$('buyerId').value.trim(),buyerName:$('buyerName').value.trim(),campaignId:$('campaignId').value.trim(),purpose:$('purpose').value.trim(),offeredPrice:price,currency:'KRW',requestedFields:fields,buyerContact:$('buyerContact').value.trim(),createdAt:isoNow(),isDemo:!!listing.isDemo,status:'OFFER_ONLY_NO_CONTRACT'});
saveFile(`GARD_INQUIRY_${request.requestId}.gard-inquiry.json`,request);setStatus(`협상 요청 JSON 저장 완료. 오너에게 별도 채널로 전달하세요. 이 단계에서 ${formatKRW(price)}의 계약·수금은 성립하지 않습니다.`);
}catch(err){setStatus(err.message,true)}});
load();
