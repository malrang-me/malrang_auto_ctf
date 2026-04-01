---
name: team-report
classification: workflow
classification-reason: "Multi-step orchestration: team composition -> parallel analysis -> HTML report generation -> browser open"
deprecation-risk: none
description: |
  Multi-agent team analysis with interactive HTML report. Dynamically spawns 3-10
  expert agents based on analysis scope, then generates a standalone HTML report
  with paginated navigation and localStorage-based Accept/Defer/Reject decision UI.
  Generates/updates feedback docs in docs/report/ for progressive improvement.
  Triggers: /team-report, team report, analysis report, HTML report,
    팀 보고서, 분석 보고서, HTML 보고서, 보고서 작성, 팀 분석,
    expert analysis, component analysis, 컴포넌트 분석, 전문가 분석
  Keywords: team, report, analysis, HTML, expert, localStorage, decision,
    팀, 보고서, 분석, 전문가, 결정, feedback, 피드백
argument-hint: "/team-report {분석 주제}"
user-invocable: true
allowed-tools:
  - Read
  - Write
  - Edit
  - Glob
  - Grep
  - Bash
  - Agent
---

# Team Report — Multi-Agent Analysis with Interactive HTML Report

## Purpose

코드베이스의 특정 주제를 전문가 에이전트가 병렬 분석하고,
결과를 페이지네이션 기반 인터랙티브 HTML 보고서로 출력하는 워크플로우 스킬.
에이전트 수는 분석 범위에 따라 3~10명으로 동적 결정.
피드백을 `docs/report/`에 YAML로 축적하여 보고서를 점진적으로 개선.

**bkit report-generator와의 차이:**
- report-generator: PDCA 완료 보고서 (Markdown)
- team-report: 다중 에이전트 분석 보고서 (Interactive HTML + localStorage + Feedback Loop)

## When to Use

- 코드베이스의 특정 측면을 깊이 분석할 때 (색상, 아키텍처, 성능 등)
- 여러 컴포넌트를 동시에 비교/분석해야 할 때
- 분석 결과를 시각적 보고서로 공유해야 할 때
- 추천 사항에 대한 의사결정 추적이 필요할 때

---

## Workflow

### Phase 1: Topic & Team Composition

1. **분석 주제 파악** — 사용자 요청에서 분석 대상 추출
2. **파일 스코프 결정** — Glob/Grep으로 관련 파일 식별
3. **동적 팀 구성** — 스코프 복잡도에 따라 에이전트 수 결정 (최소 3, 최대 10)
4. **피드백 참조** — `docs/report/` 내 기존 피드백 문서를 읽어 이전 개선 사항 반영

**동적 스케일링 기준:**

| 스코프 복잡도 | 파일 수 | 에이전트 수 | 예시 |
|--------------|---------|------------|------|
| Small        | 1-5     | 3          | 단일 컴포넌트 분석 |
| Medium       | 6-15    | 4-6        | 라우트/모듈 단위 분석 |
| Large        | 16-30   | 6-8        | 전체 UI 시스템 분석 |
| Full System  | 30+     | 8-10       | 코드베이스 전체 분석 |

**팀 구성 원칙:**
- 분석 대상 파일 수와 영역 다양성을 기준으로 에이전트 수 결정
- 각 에이전트에 명확한 스코프(파일 목록) 배정 — 스코프 겹침 금지
- 마지막 1명은 반드시 Visual QA Expert (Playwright 스크린샷)
- 에이전트 유형: 코드 분석 = `Explore`, 스크린샷 = `general-purpose`
- 파일이 적으면 에이전트를 줄이고, 많으면 영역별로 나눠 늘림

**팀 구성 예시 (Small — 3명):**
```
| Expert                | Subagent Type   | Scope                        |
|-----------------------|-----------------|------------------------------|
| Code Analysis Expert  | Explore         | Target files (all)           |
| Architecture Expert   | Explore         | Related configs, layouts     |
| Visual QA Expert      | general-purpose | Playwright screenshots       |
```

**팀 구성 예시 (Medium — 5명):**
```
| Expert                | Subagent Type   | Scope                        |
|-----------------------|-----------------|------------------------------|
| Style Expert          | Explore         | SCSS, styles                 |
| Component Expert A    | Explore         | Components 1-5               |
| Component Expert B    | Explore         | Components 6-10              |
| Architecture Expert   | Explore         | Layouts, routes, configs     |
| Visual QA Expert      | general-purpose | Playwright screenshots       |
```

**팀 구성 예시 (Large — 8명):**
```
| Expert                | Subagent Type   | Scope                        |
|-----------------------|-----------------|------------------------------|
| Landing Style Expert  | Explore         | app.scss, +page.svelte, ...  |
| Token System Expert   | Explore         | scss/ directory              |
| Component Expert A    | Explore         | Components 1-5               |
| Component Expert B    | Explore         | Components 6-10              |
| Component Expert C    | Explore         | Components 11-15             |
| API/Data Expert       | Explore         | Server routes, DB schema     |
| Architecture Expert   | Explore         | Layouts, routes, configs     |
| Visual QA Expert      | general-purpose | Playwright screenshots       |
```

### Phase 2: Parallel Analysis

1. **전문가 전원 동시 투입** — 단일 메시지에 결정된 수의 Agent 호출 포함
2. **모든 에이전트에 `run_in_background: true` 설정**
3. **각 에이전트 프롬프트에 반드시 포함:**
   - 읽어야 할 파일의 절대 경로
   - 추출할 데이터 형식 (테이블, 목록 등)
   - "Thoroughness: very thorough" 지시
4. **진행 상황 테이블 표시:**

```
| Expert              | Status   | Scope                    |
|---------------------|----------|--------------------------|
| Style Expert        | 분석 중... | app.scss, components     |
| Token Expert        | 완료     | scss/ tokens             |
| ...                 | ...      | ...                      |
```

5. **모든 에이전트 완료 대기** — 결과 수집

### Phase 3: HTML Report Generation (Paginated)

**보고서 구조 (각 항목이 1페이지 — Decision UI는 관련 페이지에 인라인 삽입):**

```
Page 1.  Analysis Team        — 팀 구성 표시
Page 2.  Executive Summary    — 핵심 수치 카드 + 주요 발견 요약
Page 3~N. Detailed Analysis   — 각 분석 영역별 상세 결과 + 인라인 추천/결정
Page N+1. Gap Analysis        — 문제점/불일치 비교 테이블 + 인라인 추천/결정
Page N+2. Visual Impression   — 스크린샷 기반 시각 분석
Page N+3. Proposed Solution   — 구체적 해결 방안
Page N+4. Priority Matrix     — 구현 우선순위
Page N+5. Decision Summary    — 전체 결정 현황 요약 + Export
```

**핵심 변경:** 기존 Recommendations 전용 페이지를 없애고,
각 추천 항목을 **관련 분석 콘텐츠 바로 아래에 인라인 삽입**한다.
에이전트가 분석 결과를 작성할 때, 추천 사항이 도출된 근거 바로 다음에
`.inline-rec` 카드를 배치해야 한다.

**레이아웃 HTML 구조 (사이드바 + 상단바 + 메인):**

```html
<div class="report-layout">

  <!-- ── 좌측 사이드바: Decision 진행 + 페이지 네비게이션 ── -->
  <aside class="sidebar" id="sidebar">
    <div class="sb-header">
      <div class="sb-title">Decisions</div>
      <div class="sb-stats" id="sbStats">
        <div class="sb-stat accept"><span class="sb-stat-num" id="statAccept">0</span>accept</div>
        <div class="sb-stat defer"><span class="sb-stat-num" id="statDefer">0</span>defer</div>
        <div class="sb-stat reject"><span class="sb-stat-num" id="statReject">0</span>reject</div>
      </div>
    </div>
    <div class="sb-progress-wrap">
      <div class="sb-progress-label">
        <span>Progress</span>
        <span id="sbProgressText">0 / 0</span>
      </div>
      <div class="sb-progress">
        <div class="sb-progress-fill" id="sbProgressFill"></div>
      </div>
    </div>
    <nav class="sb-pages" id="sbPages">
      <!-- JS에서 동적 생성 -->
    </nav>
  </aside>

  <!-- ── 메인 영역 ── -->
  <div class="main-area">
    <!-- 상단 바: 현재 페이지 타이틀 + 카운터 -->
    <header class="top-bar">
      <span class="top-bar-title" id="topBarTitle">1. Analysis Team</span>
      <span class="top-bar-counter" id="topBarCounter">1 / 8</span>
    </header>

    <!-- 페이지 콘텐츠 -->
    <div class="page" data-page="1" data-title="Analysis Team">
      <!-- 섹션 콘텐츠 -->
    </div>
    <div class="page" data-page="2" data-title="Executive Summary">
      <!-- 섹션 콘텐츠 + 인라인 .inline-rec 카드 -->
    </div>
    <!-- ... 이하 동일 -->
  </div>

</div>
```

**레이아웃 + 페이지네이션 + 사이드바 JavaScript:**

```javascript
// ── State ──
let currentPage = 1;
const pages = document.querySelectorAll('.page');
const totalPages = pages.length;

// ── Page Navigation ──
function goToPage(n) {
  if (n < 1 || n > totalPages) return;
  currentPage = n;
  const page = pages[n - 1];

  // 페이지 전환
  pages.forEach(p => p.classList.remove('active'));
  page.classList.add('active');

  // 상단 바 업데이트
  document.getElementById('topBarTitle').textContent =
    `${n}. ${page.dataset.title}`;
  document.getElementById('topBarCounter').textContent =
    `${n} / ${totalPages}`;

  // 사이드바 페이지 목록 업데이트
  document.querySelectorAll('.sb-page').forEach((item, i) => {
    item.classList.remove('active');
    if (i + 1 < n) item.classList.add('done');
    if (i + 1 === n) {
      item.classList.add('active');
      item.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  });

  // 콘텐츠 스크롤 최상단
  document.querySelector('.main-area').scrollTo({ top: 0, behavior: 'instant' });
}

function prevPage() { goToPage(currentPage - 1); }
function nextPage() { goToPage(currentPage + 1); }

// 키보드 네비게이션
document.addEventListener('keydown', (e) => {
  if (['TEXTAREA', 'INPUT', 'SELECT'].includes(e.target.tagName)) return;
  if (e.key === 'ArrowLeft')  prevPage();
  if (e.key === 'ArrowRight') nextPage();
});

// ── Sidebar Init ──
function initSidebar() {
  const container = document.getElementById('sbPages');
  pages.forEach((p, i) => {
    const pageNum = i + 1;
    const recCount = p.querySelectorAll('.inline-rec').length;

    const item = document.createElement('div');
    item.className = 'sb-page';
    item.addEventListener('click', () => goToPage(pageNum));

    // dot + 페이지 제목
    item.innerHTML = `
      <div class="sb-dot"></div>
      <span class="sb-page-label">${pageNum}. ${p.dataset.title}</span>
      ${recCount > 0
        ? `<span class="sb-badge pending" data-page="${pageNum}">0/${recCount}</span>`
        : ''}
    `;
    container.appendChild(item);
  });
}

// ── Decision Progress Tracking ──
function updateSidebarProgress() {
  const state = loadState();
  const recs = document.querySelectorAll('.inline-rec');
  let accept = 0, defer = 0, reject = 0;

  // 전체 통계 카운트
  recs.forEach(rec => {
    const id = rec.dataset.rec;
    const action = state[id]?.action;
    if (action === 'accept') accept++;
    if (action === 'defer')  defer++;
    if (action === 'reject') reject++;
  });

  document.getElementById('statAccept').textContent = accept;
  document.getElementById('statDefer').textContent = defer;
  document.getElementById('statReject').textContent = reject;

  // 프로그레스 바
  const answered = accept + defer + reject;
  const total = recs.length;
  document.getElementById('sbProgressText').textContent = `${answered} / ${total}`;
  document.getElementById('sbProgressFill').style.width =
    total > 0 ? `${(answered / total) * 100}%` : '0%';

  // 페이지별 배지 업데이트
  pages.forEach((p, i) => {
    const pageRecs = p.querySelectorAll('.inline-rec');
    if (pageRecs.length === 0) return;

    let pageAnswered = 0;
    pageRecs.forEach(rec => {
      if (state[rec.dataset.rec]?.action) pageAnswered++;
    });

    const badge = document.querySelector(`.sb-badge[data-page="${i + 1}"]`);
    if (badge) {
      badge.textContent = `${pageAnswered}/${pageRecs.length}`;
      badge.className = pageAnswered === pageRecs.length
        ? 'sb-badge complete' : 'sb-badge pending';
    }
  });
}
```

**레이아웃 CSS:**

```css
/* ── Report Layout: Sidebar + Main ── */
.report-layout {
  display: flex;
  height: 100vh;
  overflow: hidden;
}

/* ── Sidebar ── */
.sidebar {
  width: 220px;
  min-width: 220px;
  background: var(--bg-sidebar, #0d0e16);
  border-right: 1px solid rgba(255, 255, 255, 0.06);
  display: flex;
  flex-direction: column;
  overflow: hidden;
}
.sb-header {
  padding: 16px 14px 12px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.06);
}
.sb-title {
  font-size: 11px;
  font-family: 'Geist Mono', monospace;
  color: var(--text-muted, #5a5e72);
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin-bottom: 8px;
}
.sb-stats {
  display: flex;
  gap: 6px;
}
.sb-stat {
  flex: 1;
  padding: 6px 4px;
  border-radius: 6px;
  text-align: center;
  font-size: 10px;
  font-family: 'Geist Mono', monospace;
}
.sb-stat.accept { background: rgba(93, 202, 165, 0.1); color: #5DCAA5; }
.sb-stat.defer  { background: rgba(239, 159, 39, 0.1); color: #EF9F27; }
.sb-stat.reject { background: rgba(226, 75, 74, 0.1);  color: #F09595; }
.sb-stat-num {
  display: block;
  font-size: 16px;
  font-weight: 500;
}

/* Sidebar Progress */
.sb-progress-wrap {
  padding: 12px 14px;
}
.sb-progress-label {
  display: flex;
  justify-content: space-between;
  font-size: 11px;
  color: var(--text-muted, #5a5e72);
  margin-bottom: 4px;
}
.sb-progress {
  height: 3px;
  background: rgba(255, 255, 255, 0.06);
  border-radius: 2px;
}
.sb-progress-fill {
  height: 100%;
  border-radius: 2px;
  background: linear-gradient(90deg, #5DCAA5, #85B7EB);
  transition: width 0.3s ease;
}

/* Sidebar Page List */
.sb-pages {
  flex: 1;
  overflow-y: auto;
  padding: 4px 8px;
  scrollbar-width: thin;
  scrollbar-color: rgba(255,255,255,0.1) transparent;
}
.sb-page {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 7px 8px;
  border-radius: 6px;
  cursor: pointer;
  font-size: 12px;
  color: var(--text-muted, #5a5e72);
  transition: all 0.12s;
  margin-bottom: 2px;
}
.sb-page:hover {
  background: rgba(255, 255, 255, 0.04);
}
.sb-page.active {
  background: rgba(133, 183, 235, 0.08);
  color: #85B7EB;
}
.sb-page.done {
  color: #8b8fa3;
}
.sb-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: rgba(255, 255, 255, 0.1);
  flex-shrink: 0;
}
.sb-page.done .sb-dot   { background: #5DCAA5; }
.sb-page.active .sb-dot { background: #85B7EB; box-shadow: 0 0 0 2px rgba(133,183,235,0.2); }
.sb-page-label {
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.sb-badge {
  margin-left: auto;
  font-size: 9px;
  padding: 1px 5px;
  border-radius: 4px;
  font-family: 'Geist Mono', monospace;
  flex-shrink: 0;
}
.sb-badge.pending  { background: rgba(239,159,39,0.15); color: #EF9F27; }
.sb-badge.complete { background: rgba(93,202,165,0.15); color: #5DCAA5; }

/* ── Main Area ── */
.main-area {
  flex: 1;
  display: flex;
  flex-direction: column;
  min-width: 0;
  overflow-y: auto;
}

/* Top Bar */
.top-bar {
  position: sticky;
  top: 0;
  z-index: 50;
  padding: 10px 24px;
  background: var(--bg-nav, #0d0e16);
  border-bottom: 1px solid rgba(255, 255, 255, 0.06);
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.top-bar-title {
  font-size: 14px;
  font-weight: 500;
  font-family: 'Geist Mono', monospace;
  color: var(--text-primary, #e2e4ed);
}
.top-bar-counter {
  font-size: 12px;
  font-family: 'Geist Mono', monospace;
  color: var(--text-muted, #5a5e72);
}

/* ── Page Display ── */
.page {
  display: none;
  padding: 24px;
  animation: pageFadeIn 0.25s ease-out;
}
.page.active {
  display: block;
}
@keyframes pageFadeIn {
  from { opacity: 0; transform: translateY(8px); }
  to   { opacity: 1; transform: translateY(0); }
}
```

**HTML 스타일 규칙 (기존 유지):**
- Standalone HTML (외부 의존성 최소 — Google Fonts CDN만 허용)
- Dark theme (`--bg: #0a0b10` 계열)
- `Geist Mono` (headings) + `Inter` (body) 폰트
- Color swatch는 실제 색상 표시 `.swatch-color` div 사용
- 비교 테이블은 `.comparison-table` + `.color-dot` + `.tag` 패턴
- 반응형 grid 레이아웃 (`grid-template-columns: repeat(auto-fill, ...)`)

**아키텍처/UI 다이어그램 렌더링 규칙:**

보고서 내 아키텍처 구조, UI 레이아웃, 컴포넌트 트리 등을 시각화할 때
ASCII art나 코드 블록 대신 **HTML 모킹**으로 렌더링한다.

- 실제 UI 느낌으로 구성 — 컬러, 라운드 코너, 아이콘/이모지, 그림자 등 활용
- 레이어/계층 구조는 `z-index` + 겹침 or 인덴트로 시각적 깊이 표현
- 컴포넌트 박스에 실제 역할에 맞는 색상 배정 (예: HUD = teal, Canvas = blue, 슬롯 = amber)
- 화살표/연결선은 CSS border + pseudo-element 또는 SVG `<line>`으로 표현
- 호버 시 컴포넌트 설명 tooltip 표시 (`.diagram-tooltip`)
- 반응형 — 보고서 너비에 맞게 축소

```html
<!-- 다이어그램 예시 구조 -->
<div class="arch-diagram">
  <div class="arch-label">SvelteKit /battle</div>

  <div class="arch-layer" style="--layer-color: #5DCAA5;">
    <span class="arch-layer-tag">Svelte HUD (z-index: 20)</span>
    <div class="arch-row">
      <div class="arch-box arch-box--sm" style="--box-bg: #1a2e24; --box-border: #5DCAA5;">
        <span class="arch-box-icon">❤️</span> HP 바
      </div>
      <div class="arch-box arch-box--sm" style="--box-bg: #1a2e24; --box-border: #5DCAA5;">
        <span class="arch-box-icon">⏱</span> 시간
      </div>
      <div class="arch-box arch-box--sm" style="--box-bg: #1a2e24; --box-border: #5DCAA5;">
        <span class="arch-box-icon">🪙</span> 골드
      </div>
    </div>
  </div>

  <div class="arch-layer" style="--layer-color: #85B7EB;">
    <span class="arch-layer-tag">PixiJS Canvas (z-index: 10)</span>
    <div class="arch-tree">
      <div class="arch-node">pixi-viewport
        <div class="arch-children">
          <div class="arch-node arch-node--leaf">배경 타일 <code>cacheAsTexture</code></div>
          <div class="arch-node arch-node--leaf">적 Container <code>cullableChildren</code></div>
          <div class="arch-node arch-node--leaf">투사체 Container</div>
          <div class="arch-node arch-node--leaf">플레이어 Sprite</div>
          <div class="arch-node arch-node--leaf">파티클/이펙트 Container</div>
        </div>
      </div>
    </div>
  </div>

  <div class="arch-layer" style="--layer-color: #EF9F27;">
    <span class="arch-layer-tag">Skill Slots</span>
    <div class="arch-row">
      <div class="arch-box arch-box--slot" style="--box-bg: #2a1f0a; --box-border: #EF9F27;">
        슬롯1<br><small>무기</small>
      </div>
      <!-- ... 반복 -->
    </div>
  </div>
</div>
```

```css
/* ── Architecture Diagram ── */
.arch-diagram {
  padding: 20px;
  border-radius: 12px;
  background: rgba(255, 255, 255, 0.02);
  border: 1px solid rgba(255, 255, 255, 0.06);
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.arch-label {
  font-family: 'Geist Mono', monospace;
  font-size: 14px;
  color: #e2e4ed;
  font-weight: 500;
}
.arch-layer {
  border: 1px solid var(--layer-color);
  border-radius: 10px;
  padding: 14px;
  background: color-mix(in srgb, var(--layer-color) 5%, transparent);
  position: relative;
}
.arch-layer-tag {
  position: absolute;
  top: -9px;
  left: 14px;
  background: #0a0b10;
  padding: 0 8px;
  font-size: 11px;
  font-family: 'Geist Mono', monospace;
  color: var(--layer-color);
}
.arch-row {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}
.arch-box {
  padding: 8px 14px;
  border-radius: 8px;
  background: var(--box-bg);
  border: 1px solid var(--box-border);
  font-size: 12px;
  color: #e2e4ed;
  cursor: default;
  transition: transform 0.1s;
}
.arch-box:hover {
  transform: translateY(-2px);
}
.arch-box--sm { min-width: 70px; text-align: center; }
.arch-box--slot { min-width: 64px; text-align: center; }
.arch-box--slot small { color: #8b8fa3; font-size: 10px; }
.arch-box-icon { font-size: 14px; margin-right: 4px; }

/* 트리 구조 (Canvas 내부 등) */
.arch-tree {
  padding-left: 8px;
}
.arch-node {
  font-size: 12px;
  color: #b5d4f4;
  padding: 4px 0;
  font-family: 'Geist Mono', monospace;
}
.arch-node code {
  font-size: 10px;
  color: #8b8fa3;
  background: rgba(255, 255, 255, 0.06);
  padding: 1px 5px;
  border-radius: 3px;
  margin-left: 6px;
}
.arch-children {
  padding-left: 20px;
  border-left: 1px dashed rgba(133, 183, 235, 0.3);
  margin-left: 4px;
}
.arch-node--leaf {
  color: #8b8fa3;
}
.arch-node--leaf::before {
  content: '├─ ';
  color: rgba(133, 183, 235, 0.4);
}
.arch-children .arch-node--leaf:last-child::before {
  content: '└─ ';
}

/* 호버 툴팁 */
.arch-box[data-tip]:hover::after {
  content: attr(data-tip);
  position: absolute;
  bottom: calc(100% + 6px);
  left: 50%;
  transform: translateX(-50%);
  padding: 4px 10px;
  font-size: 11px;
  color: #e2e4ed;
  background: #1a1b24;
  border: 1px solid rgba(255, 255, 255, 0.1);
  border-radius: 6px;
  white-space: nowrap;
  z-index: 10;
  pointer-events: none;
}
```

**색상 가이드 (레이어별 권장):**

| 레이어 용도 | border/tag color | box-bg | 예시 |
|-------------|-----------------|--------|------|
| HUD/UI 오버레이 | `#5DCAA5` (teal) | `#1a2e24` | HP바, 타이머, 골드 |
| Canvas/렌더링 | `#85B7EB` (blue) | `#0e1a2a` | Pixi, viewport, sprite |
| Input/슬롯 | `#EF9F27` (amber) | `#2a1f0a` | 스킬 슬롯, 핫키 |
| 데이터/상태 | `#AFA9EC` (purple) | `#1a1a2e` | ECS World, Store |
| 서버/API | `#F09595` (red) | `#2a1414` | Supabase, endpoints |
| 구조/라우트 | `#8b8fa3` (gray) | `#141418` | SvelteKit 라우트 |

### Phase 4: Inline Decision UI (localStorage + Sidebar 연동)

**기존과의 차이:** Recommendations 전용 페이지를 없애고,
각 추천 항목을 **관련 분석 콘텐츠 바로 아래에 인라인 삽입**한다.
사이드바가 전체 진행 상태를 실시간 추적한다.

**인라인 추천 카드 HTML:**

```html
<!-- 분석 텍스트 중간에 삽입 -->
<p>ButtonGroup 외 3개 컴포넌트에서 #hex 직접 사용 발견...</p>

<div class="inline-rec" data-rec="R{N}">
  <div class="inline-rec-head">
    <span class="inline-rec-id">R{N}</span>
    <span class="inline-rec-title">{제목}</span>
    <span class="inline-rec-pri pri-{high|med|low}">{priority}</span>
  </div>
  <p class="inline-rec-desc">{설명}</p>
  <div class="inline-rec-btns">
    <button class="d-btn" data-action="accept"
            onclick="setDecision('R{N}','accept')">Accept</button>
    <button class="d-btn" data-action="defer"
            onclick="setDecision('R{N}','defer')">Defer</button>
    <button class="d-btn" data-action="reject"
            onclick="setDecision('R{N}','reject')">Reject</button>
    <button class="d-btn d-btn-note"
            onclick="toggleNote('R{N}')">+ note</button>
  </div>
  <div class="inline-rec-note" id="note-R{N}">
    <input type="text" placeholder="코멘트를 입력하세요..."
           oninput="saveNote('R{N}', this.value)" />
  </div>
</div>

<p>다음 분석 내용 계속...</p>
```

**배치 원칙:**
- 각 `.inline-rec`은 해당 추천의 **근거가 되는 분석 텍스트 바로 다음에** 배치
- 한 페이지에 여러 개의 `.inline-rec`이 있을 수 있음
- 추천이 없는 페이지(Team, Visual Impression 등)에는 `.inline-rec` 없음
- `data-rec="R{N}"`의 N은 보고서 전체에서 유일한 일련번호

**Decision Summary 페이지 (마지막 페이지):**
- 전체 선택 현황 집계 (사이드바와 동일 데이터)
- Export JSON 버튼 (결정 사항 다운로드)
- Copy to Clipboard 버튼 (텍스트 복사)
- Clear All 버튼 (초기화)
- 미응답 항목 하이라이트 + 해당 페이지 바로가기 링크

**localStorage 키 형식:** `core-{report-name}-decisions`

**필수 JavaScript 함수:**

```javascript
// ── Storage ──
const STORAGE_KEY = 'core-{report-slug}-decisions';
function loadState() {
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}'); }
  catch { return {}; }
}
function saveState(state) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  flashSave();
}
function flashSave() { ... }  // "Saved" 표시 잠깐 flash

// ── Decision Control ──
function setDecision(rec, action) {
  const state = loadState();
  // 동일 버튼 재클릭 시 toggle off
  if (state[rec]?.action === action) {
    delete state[rec].action;
  } else {
    state[rec] = { ...state[rec], action };
  }
  saveState(state);
  renderDecisionButtons(rec);
  updateSidebarProgress();  // 사이드바 실시간 업데이트
}

function saveNote(rec, value) {
  const state = loadState();
  state[rec] = { ...state[rec], note: value };
  saveState(state);
}

function toggleNote(rec) {
  const noteEl = document.getElementById(`note-${rec}`);
  noteEl.classList.toggle('visible');
}

// ── Rendering ──
function renderDecisionButtons(rec) {
  const state = loadState();
  const action = state[rec]?.action;
  const card = document.querySelector(`.inline-rec[data-rec="${rec}"]`);
  if (!card) return;
  card.querySelectorAll('.d-btn[data-action]').forEach(btn => {
    btn.classList.remove('chosen-accept', 'chosen-defer', 'chosen-reject');
    if (btn.dataset.action === action) {
      btn.classList.add(`chosen-${action}`);
    }
  });
}

function renderAllDecisions() {
  document.querySelectorAll('.inline-rec').forEach(card => {
    renderDecisionButtons(card.dataset.rec);
    // note 복원
    const state = loadState();
    const note = state[card.dataset.rec]?.note;
    if (note) {
      const input = card.querySelector('input');
      if (input) input.value = note;
    }
  });
}

// ── Export (Decision Summary 페이지) ──
function exportJSON() { ... }       // Blob download
function copyClipboard() { ... }    // navigator.clipboard

// ── Init ──
document.addEventListener('DOMContentLoaded', () => {
  initSidebar();
  goToPage(1);
  renderAllDecisions();
  updateSidebarProgress();
});
```

**인라인 Decision CSS:**

```css
/* ── Inline Recommendation Card ── */
.inline-rec {
  border: 1px solid rgba(239, 159, 39, 0.25);
  border-radius: 8px;
  padding: 12px 14px;
  margin: 16px 0;
  background: rgba(239, 159, 39, 0.03);
}
.inline-rec-head {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 6px;
}
.inline-rec-id {
  font-size: 11px;
  font-family: 'Geist Mono', monospace;
  color: #EF9F27;
  background: rgba(239, 159, 39, 0.15);
  padding: 2px 6px;
  border-radius: 4px;
}
.inline-rec-title {
  font-size: 13px;
  font-weight: 500;
  color: var(--text-primary, #e2e4ed);
}
.inline-rec-pri {
  font-size: 10px;
  padding: 2px 6px;
  border-radius: 4px;
  margin-left: auto;
}
.pri-high { background: rgba(226,75,74,0.15); color: #F09595; }
.pri-med  { background: rgba(239,159,39,0.15); color: #EF9F27; }
.pri-low  { background: rgba(255,255,255,0.08); color: #8b8fa3; }

.inline-rec-desc {
  font-size: 12px;
  color: var(--text-secondary, #8b8fa3);
  margin-bottom: 10px;
  line-height: 1.5;
}

/* Decision Buttons */
.inline-rec-btns {
  display: flex;
  gap: 6px;
}
.d-btn {
  padding: 5px 12px;
  font-size: 11px;
  border-radius: 5px;
  cursor: pointer;
  border: 1px solid rgba(255, 255, 255, 0.08);
  background: rgba(255, 255, 255, 0.04);
  color: #8b8fa3;
  transition: all 0.12s;
}
.d-btn:hover {
  background: rgba(255, 255, 255, 0.08);
}
.d-btn.chosen-accept {
  background: rgba(93, 202, 165, 0.15);
  color: #5DCAA5;
  border-color: rgba(93, 202, 165, 0.3);
}
.d-btn.chosen-defer {
  background: rgba(239, 159, 39, 0.15);
  color: #EF9F27;
  border-color: rgba(239, 159, 39, 0.3);
}
.d-btn.chosen-reject {
  background: rgba(226, 75, 74, 0.15);
  color: #F09595;
  border-color: rgba(226, 75, 74, 0.3);
}
.d-btn-note {
  margin-left: auto;
  font-size: 10px;
}

/* Note Input */
.inline-rec-note {
  display: none;
  margin-top: 8px;
}
.inline-rec-note.visible {
  display: block;
}
.inline-rec-note input {
  width: 100%;
  background: rgba(255, 255, 255, 0.04);
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 5px;
  padding: 5px 8px;
  font-size: 11px;
  color: var(--text-primary, #e2e4ed);
}
```

### Phase 5: Output & Open

1. **파일 저장**: `static/mockup/{report-name}.html`
2. **브라우저 자동 오픈** (Playwright MCP):
   ```
   mcp__plugin_playwright_playwright__browser_navigate → http://localhost/mockup/{report-name}.html
   ```
   - SvelteKit dev 서버(포트 80)가 항상 가동 중이므로 별도 서버 불필요
   - Playwright로 페이지를 열어 사용자 브라우저에서 바로 확인 가능
3. **결과 요약 출력**: 핵심 발견 사항 3-5줄

### Phase 6: Feedback Collection & Progressive Improvement

보고서 품질을 점진적으로 개선하기 위한 피드백 수집/문서화 시스템.

#### 6-1. 피드백 저장 위치

```
docs/report/
├── _feedback-template.yaml    # 피드백 템플릿 (최초 1회 생성)
├── color-theme-2025-03.yaml   # 보고서별 피드백
├── architecture-2025-03.yaml
└── ...
```

#### 6-2. 피드백 문서 형식 (YAML)

```yaml
# docs/report/{report-slug}-{YYYY-MM}.yaml
report_name: "로비와 랜딩 색상 테마 분석"
report_slug: "color-theme"
report_date: "2025-03-31"
report_path: "static/mockup/color-theme.html"

# ── Decisions (localStorage 자동 파싱) ──
decisions:
  - id: R1
    title: "디자인 토큰 통합"
    priority: high
    action: accept          # accept | defer | reject
    note: ""
  - id: R2
    title: "색상 팔레트 축소"
    priority: medium
    action: defer
    note: "Q2 이후 재검토"
  - id: R3
    title: "다크모드 대비 개선"
    priority: high
    action: reject
    note: "현재 대비율 충분"

# ── Manual Feedback (사용자 직접 전달) ──
feedback:
  - type: layout             # layout | content | style | ux | data | other
    detail: "Gap Analysis 페이지가 너무 길어 2페이지로 분할 필요"
    severity: medium         # low | medium | high
  - type: style
    detail: "코드 블록 폰트 크기가 너무 작음"
    severity: low

# ── Lessons Learned (자동 축적) ──
lessons:
  - category: pagination     # pagination | decision-ui | layout | data-viz | agent
    lesson: "10페이지 초과 시 페이지 셀렉트 드롭다운 너비 부족 — max-width 확대 필요"
  - category: layout
    lesson: "comparison-table이 5열 초과 시 가로 스크롤 필요"

# ── Meta ──
schema_version: 1
updated_at: "2025-03-31T14:30:00+09:00"
```

#### 6-3. 수집 방법 A — localStorage Decision 자동 파싱

보고서 생성 후 사용자가 Decision을 마친 뒤, 후속 세션에서 자동 수집:

```
1. Playwright로 보고서 페이지 열기
2. localStorage에서 decision JSON 추출
3. docs/report/{slug}-{YYYY-MM}.yaml에 decisions 섹션 작성/갱신
4. 기존 파일이 있으면 decisions만 머지 (feedback, lessons는 보존)
```

**Playwright localStorage 읽기:**
```javascript
async (page) => {
  await page.goto('http://localhost/mockup/{report-name}.html');
  const decisions = await page.evaluate(() =>
    JSON.parse(localStorage.getItem('core-{slug}-decisions') || '{}')
  );
  return JSON.stringify(decisions, null, 2);
}
```

#### 6-4. 수집 방법 B — 사용자 직접 피드백

사용자가 대화로 피드백을 전달하면:

```
1. docs/report/{slug}-{YYYY-MM}.yaml 파일 확인 (없으면 생성)
2. feedback 섹션에 새 항목 추가
3. 필요 시 lessons 섹션에도 일반화된 교훈 추가
```

**트리거 예시:**
```
보고서 피드백: Gap Analysis 테이블이 너무 길어
/team-report feedback color-theme — 코드 블록 폰트 키워줘
```

#### 6-5. 피드백 참조 (보고서 생성 시)

**Phase 1에서 반드시 수행:**

```
1. Glob으로 docs/report/*.yaml 파일 목록 확인
2. 현재 분석 주제와 관련된 피드백 문서 읽기
3. lessons 섹션에서 보고서 생성에 적용할 교훈 추출
4. 추출한 교훈을 HTML 생성 시 반영
```

**참조 우선순위:**
1. **동일 주제** 피드백 — 가장 높은 우선순위로 전부 반영
2. **lessons 섹션** — 주제 무관하게 모든 파일의 lessons를 수집하여 범용 교훈 적용
3. **feedback 섹션** — 유사 주제의 layout/style/ux 피드백 참고

**적용 예시:**
```
# docs/report/color-theme-2025-03.yaml의 lessons에서:
# - "10페이지 초과 시 pageSelect max-width 확대 필요"
# → 새 보고서가 10페이지 초과면 max-width: 300px로 변경

# - "comparison-table 5열 초과 시 가로 스크롤"
# → 새 보고서 comparison-table에 overflow-x: auto 적용
```

---

## CSS Reference (필수 스타일 목록)

보고서 생성 시 반드시 포함해야 할 CSS 클래스:

| Class | Purpose |
|-------|---------|
| `.report-layout` | 전체 레이아웃 (flex: sidebar + main) |
| `.sidebar` | 좌측 사이드바 (220px 고정) |
| `.sb-header > .sb-stats > .sb-stat` | Decision 통계 카드 (`.accept`, `.defer`, `.reject`) |
| `.sb-progress-wrap` | 프로그레스 바 영역 (`.sb-progress-fill`) |
| `.sb-pages > .sb-page` | 페이지 목록 (`.active`, `.done`, `.sb-dot`, `.sb-badge`) |
| `.main-area` | 메인 콘텐츠 영역 |
| `.top-bar` | 상단 바 — 페이지 타이틀 + 카운터 (sticky) |
| `.page` | 페이지 단위 섹션 (`data-page`, `data-title` 필수) |
| `.page.active` | 현재 표시 중인 페이지 |
| `.inline-rec` | 인라인 추천 카드 (`data-rec="R{N}"` 필수) |
| `.inline-rec-head` | 추천 헤더 (`.inline-rec-id`, `.inline-rec-title`, `.inline-rec-pri`) |
| `.d-btn` | Decision 버튼 (`.chosen-accept`, `.chosen-defer`, `.chosen-reject`) |
| `.inline-rec-note` | 코멘트 입력 (`.visible` toggle) |
| `.report-header` | 보고서 헤더 (gradient bg) |
| `.exec-summary` | Executive Summary 박스 |
| `.stats-grid > .stat-card` | 핵심 수치 카드 그리드 |
| `.swatch-grid > .swatch` | 색상 스워치 그리드 |
| `.comparison-table` | 비교 테이블 (`.color-dot`, `.tag`) |
| `.side-by-side > .side-panel` | 좌우 비교 패널 |
| `.decision-summary` | Decision Summary 페이지 — 전체 집계 |
| `.export-btn` | Export/Copy/Clear 버튼 |
| `.token-table` | 토큰 제안 테이블 (`.new-tag`) |
| `.code-block` | 코드 블록 (`.comment`, `.var`, `.val`) |
| `.team-grid > .team-card` | 팀 구성 카드 |
| `.arch-diagram` | 아키텍처/UI 다이어그램 컨테이너 |
| `.arch-layer` | 레이어 박스 (`--layer-color` 필수) |
| `.arch-layer-tag` | 레이어 라벨 (상단 태그) |
| `.arch-row` | 가로 배치 컴포넌트 행 |
| `.arch-box` | 개별 컴포넌트 박스 (`--box-bg`, `--box-border`) |
| `.arch-tree > .arch-node` | 트리 구조 (`.arch-children`, `.arch-node--leaf`) |

---

## Example Invocations

```
/team-report 로비와 랜딩 색상 테마 분석
/team-report lobby component architecture review
/team-report 성능 최적화 분석 보고서
팀 분석 보고서 작성해줘 — API 라우트 구조

# 피드백 전달
보고서 피드백: Gap Analysis 테이블이 너무 길어
/team-report feedback color-theme — 코드 블록 폰트 키워줘
```
