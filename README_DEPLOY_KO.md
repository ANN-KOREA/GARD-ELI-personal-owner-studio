# 전시장·구매자용 GitHub–Netlify 배포

이 폴더의 파일(`index.html`, `buyer.html`, `.mjs`, `.css`, `data/listings.json`, `netlify.toml`)만 **새 GitHub 저장소 최상단**에 업로드하세요.

- Netlify: Import from Git → GitHub → 해당 새 저장소 → Branch `main` → Build command 빈칸 → Publish directory `.`
- 전시장: Netlify 기본 URL `/`
- 구매자 성과 측정: Netlify 기본 URL `/buyer.html`
- 공개 목록 갱신: GitHub의 `data/listings.json`을 수정·커밋 → Netlify 연결 배포
- 시연 파일: `data/listings.json`에는 실제 고객이 아닌 **합성 시연 목록**만 기본 등록
- 오너용 실행판과 비공개 백업·승인 패키지는 절대 이 공개 저장소에 업로드하지 마세요.

원본 GARD-ELI 관련 4개 비공개 저장소를 공개로 변경할 필요가 없습니다.
