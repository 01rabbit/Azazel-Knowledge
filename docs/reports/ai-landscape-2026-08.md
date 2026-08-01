# 技術偵察レポート — AI・関連技術情勢と Azazel-Knowledge 陳腐化点検(2026-08)

作成日: 2026-08-01 / 担当: Claude Code(技術偵察) / 対象 main: `8233b4b`(583テスト基準線 / Phase 1 + Phase 2 Behavioral CTI + ADR-0010 Fabric 採用済み)

> **位置づけ。** 本レポートは**提案のみ**であり、コード・設計・ADR を一切変更しない。
> 各提案は CLAUDE.md 絶対制約1〜8(助言専用・決定論スコアリング・決定論入力規律・
> オフラインファースト・local.db 不可侵・フェイルクローズド・依存最小性・助言ルールのみ)と
> ADR-0001〜0010 を**尊重する**。教義に反する案は「非推奨」と明記し、覆すなら新 ADR が
> 要る旨を添えた(§5)。採否の最終判断はマスターに委ねる。
>
> **前月からの継続。** 本書は [`ai-landscape-2026-07.md`](ai-landscape-2026-07.md) の後継。
> 7月レポートの結論(中核教義は陳腐化せず、陳腐化は「生モノ」= モデル名・基準線・依存版に集中)は
> 8月も維持されるが、**開発基盤層で世代が1つ丸ごと進んだ**(Claude Opus 5 GA / OpenAI GPT-5.6 GA /
> MCP 2026-07-28 仕様確定)。本書はその差分と、7月の未着手提案(P1)の状態更新に焦点を絞る。

---

## (1) 要約(3行)

1. **中核教義は 8月時点でも陳腐化していない——むしろ外部から追認が強まった。** Pentera が
   「完全 agentic は methodology が毎回変わり検証不能。決定論的オーケストレーションに AI を
   内包せよ」と主張(2026-04)し、Azazel の「決定論・リプレイ可能・監査可能、LLM は説明のみ」を
   産業側の言葉で裏づけた。SANS/HITL 潮流も同方向。
2. **開発基盤層は7月から丸ごと1世代進んだ。** フロンティアは **Claude Opus 5**(2026-07-24 GA)/
   **Claude Sonnet 5**(2026-06)/ **OpenAI GPT-5.6 系**(Sol/Terra/Luna)。Codex は GPT-5.5 継続で
   Terminal-Bench 2.1 首位(83.4%)。**MCP 2026-07-28 仕様が確定**(ステートレス・OAuth/OIDC 強化)。
   → 7月 P1(開発指示書のモデル参照 de-hardcode)は**未着手のまま陳腐化差が拡大**し、優先度が上がった。
3. **プロダクト層で新規の中核変更を要する動向はない。** 産業は「静的 IOC → 行動アノマリ検知」へ
   移行中で、これは Phase 2 Behavioral CTI の方向性と一致する一方、**ML/embedding 化の誘惑**でもある。
   Azazel は決定論を維持(ADR-0009)。EPSS 副次シグナル化(7月 P2)は引き続き唯一の実在候補で、据え置き妥当。

---

## (2) 開発基盤層の新動向と本プロジェクトへの影響

### 2.1 フロンティアモデルの世代交代(7月 → 8月で1世代)

| ベンダ | 7月レポート時点 | 8月時点(本書) | 出典 |
|---|---|---|---|
| Anthropic | Opus 4.8(2026-05)| **Opus 5**(2026-07-24 GA)/ **Sonnet 5**(2026-06)| [Claude Timeline(Opus 5)](https://www.scriptbyai.com/anthropic-claude-timeline/) / [Every Claude Model](https://claudefa.st/blog/models) |
| OpenAI | GPT-5.5(2026-04)| **GPT-5.6 系 GA**(Sol/Terra/Luna)。Codex 推奨は引き続き GPT-5.5 | [OpenAI GPT-5.6](https://openai.com/index/gpt-5-6/) / [Codex Changelog(April 2026)](https://www.developersdigest.tech/blog/codex-changelog-april-2026) |
| コーディング実測 | — | Terminal-Bench 2.1: **Codex CLI + GPT-5.5 が 83.4% で首位**、Claude Code + Opus 4.8 が 78.9% | [morphllm リーダーボード](https://www.morphllm.com/ai-coding-agent) |

**本プロジェクトへの影響。** `docs/development-guide.md` §2B の「Claude Code(指揮)× OpenAI Codex(実装)を
worktree 分離で回す」体制、すなわち**二社フロンティア併用による敵対的多様性**は世代が進んでも骨格として有効。
だが指示書内の**生モノ**——`--model <codex-model>` プレースホルダ、および「583テスト」の直書き——は世代交代で
陳腐化しやすい。7月レポートが P1 で「モデル参照を現行世代に更新し、基準線テスト数を1箇所参照に集約せよ」と
提案したが、**現 main の指示書は依然 583 直書き・プレースホルダのまま**であり、世代差が Opus 4.8→5 /
GPT-5.5→5.6 と開いたぶん未着手コストが増えた。→ §4 P1 で再掲・優先度引き上げ。

### 2.2 Claude Code の新機能(Dynamic Workflows / Performance Outcomes / Plugins)

- **Dynamic Workflows**(2026-06 投入): リード agent が単一セッションで数十〜数百の並列 subagent を
  計画・ファンアウトする。加えて **Performance Outcomes**——別の grader(採点役)が各 subagent を
  ルーブリック合格まで差し戻す——が組み合わさる([MarkTechPost 2026 ガイド](https://www.marktechpost.com/2026/06/14/claude-code-guide-2026-25-features-with-examples-demo/))。
- **Plugins** は CLAUDE.md / skills / subagents / slash commands / hooks / MCP servers を1インストール単位に
  束ねる包装層。マーケットプレイスは 9,000+ 規模([ScriptByAI リソースリスト](https://www.scriptbyai.com/claude-code-resource-list/))。

**本プロジェクトへの影響。** 「Performance Outcomes(grader が合格まで差し戻す)」は、本リポジトリの
**敵対的レビュー・ループ(緑まで反復)を機構化した相似形**であり、Option B(Codex 外部実装 + Claude 敵対レビュー)を
Claude Code ネイティブの subagents + grader で置換しうる。ただし7月結論どおり、**指揮官と実装者を別ベンダに
分ける敵対的多様性**(写経レビューの回避)を単純な機能置換で捨てるべきではない。→ §4 P1 の注記で「評価タスクとして
記録・即時変更しない」を維持。なお本リポジトリの `.claude/settings.json` は `codex exec` 前置マッチ許可 +
`danger-full-access` 明示拒否で既に固められており、ネイティブ subagents 併用時も同じ「サンドボックス逸脱を
機械的に禁止」原則を延長すればよい。

### 2.3 MCP 2026-07-28 仕様の確定と供給網ガバナンス

- **MCP 2026-07-28 が最終仕様として確定**(RC ロック 2026-05-21 → 確定 2026-07-28)。launch 以来最大の改訂で、
  **ステートレス・コア**(`initialize`/`initialized` ハンドシェイク廃止、セッション状態をリクエスト・メタデータに移動)、
  6本の SEP による OAuth/OIDC 整合強化、**RFC 9207 準拠の `iss` 検証(SEP-2468)**によるミックスアップ攻撃緩和、
  12ヶ月の deprecation ライフサイクル方針を含む([MCP 仕様 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28) / [MCP Blog RC](https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/))。
- **供給網リスクは依然高い。** 公式レジストリは 3,012 サーバ(2026-03)だが **OAuth 採用は 8.5% のみ**。
  confused deputy / token passthrough / tool poisoning / SSRF / rogue server registration の5ベクタが定義され、
  推奨統制は「署名・アテステーション・版固定つき許可リスト、新規サーバ登録を変更管理イベント扱い」
  ([Wiz MCP セキュリティ](https://www.wiz.io/academy/ai-security/model-context-protocol-security) / [NSA CSI: MCP Security(PDF)](https://www.nsa.gov/Portals/75/documents/Cybersecurity/CSI_MCP_SECURITY.pdf))。

**本プロジェクトへの影響。** 7月と結論不変——**Azazel-Knowledge のランタイムは MCP を使わない**
(コア依存は stdlib + PyYAML + idna + PyNaCl のみ、Fabric も `api` extra 限定)。MCP は**開発ツールチェーン側**にのみ存在しうる。
プロダクトの攻撃面は増えていない。仕様確定と NSA/Wiz の統制勧告は、7月 P4(開発時 MCP 衛生の方針化)を
**より具体化できる材料**になった(許可リスト・署名・版固定・登録=変更管理という語彙が標準化された)。→ §4 P4 に反映。

---

## (3) プロダクト設計層の新動向と本プロジェクトへの影響

### 3.1 「決定論 + agentic」ハイブリッドが産業の言葉になった(教義の追認)

- Pentera(Noam Hirsch, 2026-04-15)は明快に主張する:「**完全 agentic はテスト手法が実行ごとに変わり、
  セキュリティが本当に改善したか検証不能**になる。決定論的オーケストレーションに AI を内包し、
  同一条件下で**リプレイ可能**な攻撃チェーンを保て」。HITL でもこの**変動性**の根本問題は解けない、とする
  ([The Hacker News: Deterministic + Agentic AI](https://thehackernews.com/2026/04/deterministic-agentic-ai-architecture.html))。
- 学術側でも Auto Threat AI が「**決定論的 indicator 抽出 + bounded risk scoring + evidence-first 説明可能性 +
  HITL ガバナンス**」を framework 化([IJRASET: Auto Threat AI](https://www.ijraset.com/best-journal/auto-threat-ai-an-agentic-and-explainable-framework-for-automated-cyber-threat-intelligence-extraction))。

**本プロジェクトへの影響。** これは Azazel の中核契約——**7要素タプルによる byte-identical replay**(F-2/F-8)、
**完全な `reason[]`**、**LLM は説明・レポートのみ**(README 非目標)——を産業/学術の語彙で**そのまま裏づけた**。
Pentera の「replayed under the same conditions」は Azazel の `query_as_of` 貫通と決定論リプレイの言い換えに等しい。
陳腐化どころか**差別化研究姿勢の追い風**(ADR-0008「CTI 最適化された遅延防御」)。→ 中核を動かす提案は不要。§5 で「現行維持」。

### 3.2 「静的 IOC → 行動アノマリ検知」への移行(Phase 2 と一致、ただし ML 化の誘惑)

- 2026 の CTI 潮流は「静的な IOC から**行動アノマリ検知**へ」の転換が明確で、SOC 評価指標も
  alert 量から MTTD/dwell time/回避コストへ移行([Seceon 2026 トレンド](https://seceon.com/cybersecurity-trends-2026/) / [Fortinet 2026 トレンド](https://www.fortinet.com/resources/cyberglossary/cybersecurity-trends-2026))。CTI 市場は 2025 の $14.1B → 2026 $17.2B(CAGR 22%)([TBRC CTI マーケット](https://www.thebusinessresearchcompany.com/report/cyber-threat-intelligence-global-market-report))。
- 商用プラットフォームの主流実装は **ML ベースの behavioral scoring / 予測相関**。

**本プロジェクトへの影響。二面性は7月と同じで、8月はさらに鮮明。**
(i) 「行動を軸に脅威を特徴づける」という**方向**は Phase 2 Behavioral CTI(reaction → behavior_pattern →
分類 → 類似度/再現性 → 助言)と**合致**しており陳腐化していない。むしろ産業のメインストリーム化が追い風。
(ii) だが商用の**手段**(ML/embedding/clustering)は Azazel が**意図的に採らない**(ADR-0009 が生成・類似度・
スコアリングでの ML/embedding/clustering/LLM を明示禁止、決定論・リプレイ・非属性を選択)。この乖離は弱みではなく、
Pentera 的な「検証可能性」論拠で**正当化される差別化**。→ §5 で「ML 化は非推奨(覆すなら新 ADR)」を再掲。

### 3.3 標準(STIX / TAXII)と脆弱性優先度(KEV / EPSS)

- **STIX 2.1 / TAXII 2.1 が依然 OASIS 現行標準**。STIX 2.2 の公表は 8月時点でも確認できず
  ([OASIS CTI TC](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=cti) / [CTI FAQ](https://oasis-open.github.io/cti-documentation/faq.html))。→ ADR-0002/0005 は陳腐化せず、追随不要。
- **EPSS は依然 ML ベースの悪用確率モデル**(30日以内の悪用確率、0〜1)。2026 の推奨実務は
  「**KEV=現在の確定事実(24h 以内パッチ)/ EPSS=近未来の確率(> 0.5 で先行)**」という
  KEV×EPSS 合成([Picus: CVSS/EPSS/KEV/SSVC/LEV/PXS 比較](https://www.picussecurity.com/resource/blog/comparing-cvss-epss-kev-ssvc-lev-and-pxs-from-scores-to-security-proof) / [isMalicious: EPSS 2026](https://ismalicious.com/posts/epss-exploit-prediction-scoring-system-patch-prioritization))。

**本プロジェクトへの影響。** 7月 P2(EPSS を**副次コンテキスト**として決定論・オフラインの枠内に取り込む設計スパイク)は
8月も唯一の実在するプロダクト機能拡張候補。**EPSS が ML 由来の確率値**である点は、Azazel の決定論方針と
「確定事実(KEV)を主・確率(EPSS)を副次」の扱いで両立させる設計(as-of 世代固定 + bundle 取込、
7要素タプルに混ぜない)が引き続き成立する。実装は本レポートの範囲外。→ §4 P2 に状態維持で再掲。

---

## (4) 優先度付きアップデート提案

各項目: **提案 / 根拠+出典 / 想定工数 / リスク / 絶対制約との整合性**。すべてマスター判断待ち。
P2〜P4 は7月からの**継続提案**(状態を更新して再掲)。

### P1(高・低コスト・優先度↑): 開発指示書の生モノ更新(世代差が拡大したため着手推奨)

- **提案**: `docs/development-guide.md` の (a) `--model <codex-model>` プレースホルダを現行世代の実名
  (例示として Codex 推奨 = GPT-5.5、Claude 側 = Opus 5)へ更新、(b) 「583テスト」の直書きを1箇所参照に集約
  (基準線変動時の追随点を単一化)、(c) 注記として「Claude Code の Dynamic Workflows / Performance Outcomes /
  ネイティブ subagents は Option B の代替候補だが、**指揮官と実装者を別ベンダに分ける敵対的多様性**を失うため
  即時採用しない。評価は別タスク、採否は ADR 相当の判断を要する」を明記。
- **根拠+出典**: 世代交代([Opus 5](https://www.scriptbyai.com/anthropic-claude-timeline/) / [GPT-5.6](https://openai.com/index/gpt-5-6/) / [Terminal-Bench 実測](https://www.morphllm.com/ai-coding-agent))、Claude Code 新機能([MarkTechPost](https://www.marktechpost.com/2026/06/14/claude-code-guide-2026-25-features-with-examples-demo/))。7月 P1 が未着手のまま世代差が拡大した点。
- **想定工数**: 0.5 人日(文書のみ、コード変更なし)。
- **リスク**: 低。着手の遅れそのものが害(陳腐化差の累積)。
- **絶対制約整合性**: 抵触なし(開発体制文書。ランタイム挙動・依存・スコアリングに触れない)。

### P2(中・中コスト・7月から状態維持): EPSS をオフライン・決定論の枠内で助言シグナル化する設計スパイク

- **提案**: EPSS スコアを**新規フィード adapter**(クエリパス外、worker/bundle 経由)として取り込み、
  `/v1/context` の助言に**副次コンテキスト**として付す設計スパイクを起票する。スコアリング本体の7要素決定論
  タプルには**入れず**(F-2/F-8 の byte-identical replay を破らない)、別 config 世代ハッシュ下で
  「EPSS as-of 世代」を固定して決定論リプレイ可能にする。**実装は提案段階では行わない**(起票まで)。
- **根拠+出典**: KEV×EPSS 合成の実務標準性([Picus 比較](https://www.picussecurity.com/resource/blog/comparing-cvss-epss-kev-ssvc-lev-and-pxs-from-scores-to-security-proof) / [isMalicious 2026](https://ismalicious.com/posts/epss-exploit-prediction-scoring-system-patch-prioritization))。既存 `cve_exploited`(KEV 由来, 重み 0.15)の自然な拡張。
- **想定工数**: 設計スパイク 1〜2 人日。実装(採用時)は adapter + 世代管理 + テストで 5〜8 人日相当。
- **リスク**: 中。(a) EPSS は日次更新の確率値 → as-of 世代固定 + bundle 取込で決定論とオフラインを両立。
  (b) スコアリング本体に混ぜると F-2/F-8 を破る → 混ぜない設計が必須。(c) 新フィード = feeds/ の adapter 追加で
  コア依存追加は伴わない。
- **絶対制約整合性**: 満たせる設計が存在する(①助言専用: 副次のみ・書込は worker 単一ライタ、②決定論: 別世代
  ハッシュ + as-of 固定、④オフラインファースト: 取得は worker/bundle、⑦依存最小性: 既存経路で新規 pip なし)。
  **重み表を変える案なら ADR-0006 改訂が必要**——今回は副次コンテキスト止まりを推奨。

### P3(中・低コスト・7月から状態維持): 依存とランタイムの陳腐化点検

- **提案**: `pyproject.toml` の `requires-python = ">=3.11"` と `api`/`dev` の未ピン依存
  (fastapi/pydantic/uvicorn/pytest/httpx)について、(a) サポート下限 Python の見直し、(b) メジャー固定の可否、
  (c) pydantic v2 前提の明記、を点検する短報を起こす。**コア依存(stdlib+PyYAML+idna+PyNaCl)は変更しない**。
  Fabric は ADR-0010 どおり v0.3.0 タグ固定・`api` extra 限定を維持(境界のみ・追加的・wire shape 不変)。
- **根拠+出典**: 内部保守衛生(外部トレンドではなく陳腐化点検として計上)。Pi 4 の resource budget
  (architecture.md, < 2GB RSS)を壊さない範囲に限る。
- **想定工数**: 0.5〜1 人日(点検短報のみ、依存追加はしない)。
- **リスク**: 低〜中。API 依存のメジャー更新は fastapi/pydantic 破壊的変更を招きうるため点検止まり、更新自体は
  別 PR + テスト全緑を条件にする。
- **絶対制約整合性**: ⑦依存最小性を**強化する**方向。新規依存追加を伴わない限り抵触なし。

### P4(中・低コスト・7月から具体化): 開発ツールチェーンの供給網衛生を方針化(MCP 2026-07-28 準拠語彙で)

- **提案**: `docs/development-guide.md` または新規短節に「開発時に外部 MCP サーバ/エージェント拡張を接続する
  際の最小衛生」を明文化。MCP 2026-07-28 と NSA/Wiz 勧告の標準語彙を採る:**署名・アテステーション・版固定つき
  許可リスト、新規サーバ登録=変更管理イベント、OAuth/OIDC(RFC 9207 `iss` 検証)前提、ネットワーク要求の遮断**。
  **プロダクトへの MCP 導入は現時点で行わない**ことも同時に明記。
- **根拠+出典**: [MCP 仕様 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28) / [MCP Blog RC](https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/) / [Wiz MCP セキュリティ](https://www.wiz.io/academy/ai-security/model-context-protocol-security) / [NSA CSI: MCP Security](https://www.nsa.gov/Portals/75/documents/Cybersecurity/CSI_MCP_SECURITY.pdf)。
- **想定工数**: 0.5 人日(文書のみ)。
- **リスク**: 低。未明文化のまま外部 MCP を繋ぐことのほうがリスク。
- **絶対制約整合性**: 抵触なし。オフラインファースト/依存最小性の精神を開発工程側へ延長する。

---

## (5) 据え置き・非推奨と判断した項目とその理由

| 項目 | 判断 | 理由 |
|---|---|---|
| **中核教義(助言専用・決定論・オフライン・非属性・LLM は説明のみ)の変更** | 現行維持 | Pentera「決定論オーケストレーションに AI を内包・リプレイ可能性が検証の要」([THN](https://thehackernews.com/2026/04/deterministic-agentic-ai-architecture.html))と Auto Threat AI(決定論抽出 + bounded scoring + HITL)([IJRASET](https://www.ijraset.com/best-journal/auto-threat-ai-an-agentic-and-explainable-framework-for-automated-cyber-threat-intelligence-extraction))が教義を追認。動かす動機なし。 |
| **STIX/TAXII のバージョン追随** | 現行維持 | STIX 2.1 / TAXII 2.1 が依然 OASIS 現行標準。2.2 は未公表([OASIS CTI TC](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=cti))。ADR-0002/0005 は陳腐化せず。 |
| **ML/embedding/LLM ベースの behavioral scoring 採用** | **非推奨** | ADR-0009 が生成・類似度・スコアリングでの ML/embedding/clustering/LLM を明示禁止。ADR-0006 の決定論・完全 `reason[]`・byte-identical replay と正面衝突。商用潮流([Seceon](https://seceon.com/cybersecurity-trends-2026/))はあるが検証可能性の論拠で決定論選択が正当化される。**覆すなら shadow-only 節を超越する新 ADR が必須**。 |
| **プロダクトへの MCP 導入 / 助言 API の MCP サーバ公開** | 据え置き | 2026-07-28 で仕様は成熟したが供給網リスク(OAuth 採用 8.5%、5攻撃ベクタ)は継続([Wiz](https://www.wiz.io/academy/ai-security/model-context-protocol-security))。offline-first・依存最小性・助言専用に照らし価値対リスク過大。将来議論なら ADR 案件。 |
| **Claude Code ネイティブ subagents で Codex を置換** | 据え置き(評価タスク化) | Dynamic Workflows / Performance Outcomes は敵対的レビュー・ループの相似形だが、**別ベンダ併用による敵対的多様性**を失う。P1 の注記で評価タスクとして記録し即時変更しない。 |
| **SQLite → PostgreSQL 移行** | 据え置き | ADR-0003 の移行トリガ(実測書込負荷)が未達。Pi 4 budget 内は SQLite WAL 継続が妥当。 |
| **予測型(EPSS を主指標化)スコアリング** | 非推奨(副次のみ可) | EPSS は ML 由来の確率値。確定事実(KEV)主・確率(EPSS)副次の決定論方針を主指標化で崩すべきでない。P2 は副次コンテキスト止まりに限定。 |

---

## 付記: 陳腐化点検の総括(2026-08)

- **教義は 8月時点でも陳腐化しておらず、Pentera/Auto Threat AI/SANS の潮流に追認されている。** 中核を動かす提案はない。
- **陳腐化が起きているのは「生モノ」——特にモデル世代**(Opus 4.8→5 / GPT-5.5→5.6、7月から1世代進行)。
  7月 P1(開発指示書の de-hardcode)は未着手のため差が広がり、**8月は優先度を上げて再掲**(P1)。
- **プロダクト機能拡張候補は依然 P2(EPSS 副次シグナル)のみ**で、決定論・オフライン・依存最小の枠内に収まる設計が存在。
  実装は本レポートの範囲外(設計スパイク起票まで)。
- **MCP は 2026-07-28 で仕様確定したが、本プロジェクトのランタイムには無関係**(開発工程側の衛生方針化 = P4 に反映)。

### 参照一覧(主要出典)

- Claude モデル世代(Opus 5 / Sonnet 5): <https://www.scriptbyai.com/anthropic-claude-timeline/> / <https://claudefa.st/blog/models>
- OpenAI GPT-5.6: <https://openai.com/index/gpt-5-6/> / Codex Changelog: <https://www.developersdigest.tech/blog/codex-changelog-april-2026>
- コーディングエージェント実測(Terminal-Bench 2.1): <https://www.morphllm.com/ai-coding-agent>
- Claude Code 新機能(Dynamic Workflows / Performance Outcomes): <https://www.marktechpost.com/2026/06/14/claude-code-guide-2026-25-features-with-examples-demo/>
- MCP 2026-07-28 仕様: <https://modelcontextprotocol.io/specification/2026-07-28> / RC Blog: <https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/>
- MCP セキュリティ(Wiz / NSA CSI): <https://www.wiz.io/academy/ai-security/model-context-protocol-security> / <https://www.nsa.gov/Portals/75/documents/Cybersecurity/CSI_MCP_SECURITY.pdf>
- 決定論 + agentic(Pentera / THN): <https://thehackernews.com/2026/04/deterministic-agentic-ai-architecture.html>
- Auto Threat AI(決定論抽出 + HITL): <https://www.ijraset.com/best-journal/auto-threat-ai-an-agentic-and-explainable-framework-for-automated-cyber-threat-intelligence-extraction>
- CTI 潮流(行動アノマリ / 市場): <https://seceon.com/cybersecurity-trends-2026/> / <https://www.fortinet.com/resources/cyberglossary/cybersecurity-trends-2026>
- EPSS / KEV 優先度(Picus / isMalicious): <https://www.picussecurity.com/resource/blog/comparing-cvss-epss-kev-ssvc-lev-and-pxs-from-scores-to-security-proof> / <https://ismalicious.com/posts/epss-exploit-prediction-scoring-system-patch-prioritization>
- OASIS STIX/TAXII 現行(2.1): <https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=cti> / <https://oasis-open.github.io/cti-documentation/faq.html>
</content>
</invoke>
