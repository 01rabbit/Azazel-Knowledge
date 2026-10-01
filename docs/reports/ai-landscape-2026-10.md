# 技術偵察レポート — AI・関連技術情勢と Azazel-Knowledge 陳腐化点検(2026-10)

作成日: 2026-10-01 / 担当: Claude Code(技術偵察) / 対象 main: `f29c29d`(Phase 1 + Phase 2 Behavioral CTI + AZ-06 deception effectiveness / Outcome-as-Evidence / Fabric v0.9.0rc2 / ADR-0001〜0018 まで反映)

> **位置づけ。** 本レポートは**提案のみ**であり、コード・設計・ADR を一切変更しない。
> 各提案は CLAUDE.md 絶対制約1〜8(助言専用・決定論スコアリング・決定論入力規律・
> オフラインファースト・local.db 不可侵・フェイルクローズド・依存最小性・助言ルールのみ)と
> ADR-0001〜0018 を**尊重する**。教義に反する案は「非推奨」と明記し、覆すなら新 ADR が
> 要る旨を添えた(§5)。採否の最終判断はマスターに委ねる。
>
> **前月からの継続。** 本書は [`ai-landscape-2026-09.md`](ai-landscape-2026-09.md) の後継。
> 9月レポートの結論(中核教義は陳腐化せず、陳腐化は「生モノ」= モデル名・基準線・依存版・
> 外部データ版に集中)は10月も維持される。**9月の宿題のうち P1(EPSS モデル版の世代固定)は
> [ADR-0014](../adr/0014-epss-advisory-ingest.md) の `epss_generation` 設計に反映済みで解決**
> (§3.2)。残る P2(ATT&CK v19 内容移行点検)と P3(README 基準線整合)は**外部版が動いて
> いない/文書が未更新のため依然有効・未着手**。本書の核心は、**9月末(2026-09-22)に
> Claude・OpenAI 双方でフロンティア世代が同時に1段上がった**ことと、**Claude Code の新機能
> (Agent Teams・AGENTS.md 直読み・sandbox strictAllowlist)が委任プロトコル §2B/§2C に機構的に
> 噛み合う**ことの2点。いずれも生モノの単一情報源更新と開発工程整合であり、中核契約は動かさない。

---

## (1) 要約(3行)

1. **中核教義は10月時点でも陳腐化しておらず、外部からの追認はさらに強まった。** agentic SOC 市場は
   実務変曲点に達したが、要求は一様に **「透明・説明可能・監査可能(transparent / explainable /
   auditable)」**。Intezer らは「LLM 推論 + **決定論フォレンジック** = 再現可能・監査対応エビデンス」を
   掲げ、「何をしたかだけでなく**なぜ**したかを全ステップ記録・レビュー可能に」と明言——本ノードの
   助言専用・決定論・完全な `reason[]`・監査チェーン設計が**市場要件そのもの**になった。
2. **開発基盤層で9月末(2026-09-22)に二重の世代バンプ。** Anthropic が **Claude Opus 5.5**(「我々が
   フロンティアのペース調整を呼びかけて以降の最初のモデル」)、OpenAI が **GPT-6 世代(Sol/Luna/Astra)**を
   同日投入。生モノの単一情報源(`development-guide.md` §0 → 本レポート最新号)を **Claude=Opus 5.5・
   Codex=GPT-6** に更新するのが今月の主アクション(§4 P1)。Claude Code は **Agent Teams・AGENTS.md 直読み・
   `sandbox.network.strictAllowlist`** を追加し、委任プロトコル §2B/§2C に機構的に噛み合う(§4 P2)。
3. **プロダクト層の外部版は据え置き(EPSS v5・ATT&CK v19.2・STIX/TAXII 2.1 変化なし)。** 9月 P1(EPSS
   モデル版固定)は ADR-0014 の `epss_generation` に反映済み・**解決**。P2(ATT&CK v19 内容移行点検)と
   P3(README 基準線 583 の整合)は**継続**(README は単一情報源 1213 と乖離が拡大)。**ATT&CKcon 7.0
   (2026-10)は v20 の前触れになりうる watch 項目**。中核を動かす提案は今月も不要。

---

## (2) 開発基盤層の新動向と本プロジェクトへの影響

### 2.1 フロンティアモデル: 9月末に Claude・OpenAI 双方が同時に世代バンプ

| ベンダ | 9月時点(前号) | 10月時点(本書) | 出典 |
|---|---|---|---|
| Anthropic | Opus 5(2026-07-24 GA)/ Sonnet 5 | **Opus 5.5**(2026-09-22)。「pacing the frontier を呼びかけて以降の最初のモデル」。Opus 5 比 **~30% 高速・40% 低コスト/タスク**、FrontierCode で **GPT-6 Astra を ~20% のコストで上回る**。現行 lineup = Opus 5.5 / Fable 5.1 / Sonnet 5 / Haiku 4.5 / **Mythos 5.1(restricted)** | [9to5Mac: Opus 5.5](https://9to5mac.com/2026/09/22/anthropic-upgrades-claude-with-new-opus-5-5-model-details-here/) / [Anthropic: Opus 5](https://www.anthropic.com/news/claude-opus-5) / [claudefa.st: 全モデル](https://claudefa.st/blog/models) |
| OpenAI | Codex 既定 = GPT-5.6 "Sol" | **GPT-6 世代へ**。**GPT-6 Sol / Luna** を 2026-09-22 に追加(GPT-5.6 版より高性能・Astra より安価)、**GPT-6 Astra** が Terminal-Bench 4.0 で **58.2% 首位**。Codex は3つの GPT-6 を提供 | [9to5Mac: GPT-6 二機種追加](https://9to5mac.com/2026/09/22/openai-upgrading-chatgpt-and-codex-with-two-more-gpt-6-models/) / [Codex changelog](https://developers.openai.com/codex/changelog) / [morphllm: best coding agents 9/2026](https://www.morphllm.com/best-ai-coding-agents-2026) |

**本プロジェクトへの影響。** (a) **生モノ churn はむしろ加速**した。9月号が「Opus 5 据え置き・churn 鈍化」と
記したが、10月は Claude・OpenAI が**同日(2026-09-22)に揃って1世代上げた**。これは `development-guide.md` §0 が
**最新推奨世代を本レポート最新号に単一情報源化**した判断の正しさを裏づける——直書きしていれば今月だけで
3文書(CLAUDE.md・development-guide・AGENTS.md 相当)の修正が要るところ、本書が最新世代を確定するだけで済む
(§4 P1)。確定値:**Claude 側 = Opus 5.5、Codex 側 = GPT-6(Sol/Luna/Astra)**。
(b) ベンチは**両者ともフロンティア**(GPT-6 Astra 58.2% @ Terminal-Bench 4.0、Opus 5.5 は FrontierCode で
Astra を低コストで上回る)で、どちらかが明白に劣るわけではない。よって「**指揮官・敵対的レビュー = Claude、
実装労働 = Codex**」の分業(§2/§2B)は、能力勾配ではなく**別ベンダ併用による敵対的多様性**(写経レビュー回避)で
正当化される——この論拠は世代バンプで変わらない(§5)。
(c) Anthropic の **「pacing the frontier(フロンティアのペース調整)」宣言**は、本プロジェクトの
「churn より決定論・再現性」という価値観と**外形的に共鳴**する(ただしこれはモデル供給側の話であり、
本ノードの教義そのものとは独立。追認として過大評価しない)。

### 2.2 Claude Code: Agent Teams / AGENTS.md 直読み / sandbox strictAllowlist が委任教義に噛み合う

- **Agent Teams**(coordinated subagents + messaging)と **nested subagents が既定で depth 3** まで。
  未完のバックグラウンド agent を含むセッションの resume も改善。
- **AGENTS.md を直接読む**ようになった(従来は CLAUDE.md からの import が必要。CLAUDE.md が無いリポでは
  AGENTS.md をそのまま読む)。
- **`/sandbox` ダイアログ**(sandbox mode / unsandboxed fallback / excluded commands を一覧)、
  **per-command `allowed_domains`**(Bash/PowerShell/Monitor がホスト単位でレビュー・許可)、
  **`sandbox.network.strictAllowlist`**(非許可ホストを**無確認で拒否**)。既定 Opus モデルが Opus 5.5 に。
- 出典: [releasebot: Claude Code(9月)](https://releasebot.io/updates/anthropic/claude-code) /
  [Claude Code changelog(9月)](https://www.gradually.ai/en/changelogs/claude-code/) /
  [What's new](https://code.claude.com/docs/en/whats-new)。

**本プロジェクトへの影響。** 3点の直接的含意がある(→ §4 P2)。
(a) **AGENTS.md 直読みは本リポに直接効く。** 本リポの AGENTS.md は **Codex(実装者)の憲法**で、worktree 内で
Codex が自動で読む前提(§3)。いまや**指揮官 Claude Code もこれを自動で読む**ため、「CLAUDE.md(指揮官規範)×
AGENTS.md(実装者規範)」の**二重規範が両方 Claude Code の文脈に入る**。両者が矛盾しない(とくに絶対制約1〜8・
テスト基準線・git 規律の記述がズレない)ことを点検し、`development-guide.md` §3 に「両ファイルが Claude Code に
読まれる前提」を一行注記する価値がある。
(b) **`strictAllowlist` / `allowed_domains` は §2B「network 要求は即中断」・§2C「許可リスト運用」を Claude Code の
機構で強制できる。** 指揮官セッションで `sandbox.network.strictAllowlist` を既定 ON とし、`codex exec` 配線の
オフライン規律(§2B 規約4)を二重化する評価に値する。
(c) **Agent Teams は Option B(外部 Codex + 敵対的レビュー・ループ)の機構的相似をさらに強めた。** これは
「native subagents で Codex を置換できるか」の検討材料を増やすが、§5 のとおり**別ベンダ併用の敵対的多様性**を
失う判断なので即時置換はしない(ADR 相当の評価タスク維持)。

### 2.3 MCP: 2026-07-28 仕様が stateless core + MCP Apps、エコシステムは巨大化

- **2026-07-28 仕様**: handshake(initialize/initialized)と `Mcp-Session-Id` を**廃した stateless core**
  (プロトコルメタデータは各リクエストの `_meta` で搬送)、**MCP Apps(server-rendered UI)**、長時間処理の
  **Tasks 拡張**、**OAuth/OpenID Connect 整合**の認可。新ロードマップの重点は **agentic messaging primitives・
  agent identity / enterprise security・SDK DX**。
- **エコシステムは巨大化**: Glama レジストリに **19,831+ サーバ**、SDK 月間 **97M ダウンロード**、
  Anthropic/OpenAI/Google/Microsoft が後ろ盾。
- 出典: [MCP ロードマップ](https://blog.modelcontextprotocol.io/posts/mcp-roadmap/) /
  [2026-07-28 仕様(RC)](https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/) /
  [WorkOS: MCP in 2026](https://workos.com/blog/everything-your-team-needs-to-know-about-mcp-in-2026)。

**本プロジェクトへの影響。** 結論は9月から不変——**本ノードのランタイムは MCP を使わない**(コア依存は
stdlib + PyYAML + idna + PyNaCl、Fabric も `api`/`taxii` extra 限定)。新事実の方向はいずれも**非導入判断を追認**する:
**MCP Apps(server-rendered UI)はプロダクト攻撃面を増やす**ため、助言 API を MCP サーバ化しない判断(§5)は
より妥当に。開発工程側 §2C は**微更新**できる——「認可は OAuth/OIDC 整合前提」「stateless core(sticky routing 不要)」を
語彙に反映(導入する場合の衛生であり、プロダクト導入とは別)。

---

## (3) プロダクト設計層の新動向と本プロジェクトへの影響

### 3.1 【教義の強い追認】agentic SOC が「説明可能・監査可能」を要件化、決定論フォレンジック併用が潮流に

- 2026 は enterprise SOC の**実務変曲点**だが、要求は一様に **「透明・説明可能・監査可能な AI 成果」**。agentic SOC は
  copilot 止まりと異なり「アラートではなく攻撃を自律的に優先し、**全判断に traceable reasoning を提供**」する方向。
- **Intezer** は agentic AI 推論と**決定論フォレンジック手法**(メモリスキャン・リバースエンジニアリング・コード解析)を
  組み合わせ、「**再現可能・監査対応(reproducible, audit-ready)のエビデンス**」を生成すると明言。SOC は agent に
  「**何をしたかだけでなく、なぜしたか**——全判断・全ステップ・参照した全シグナルを記録・説明・レビュー可能に」を期待。
- 出典: [Elastic: 2026 is the year to upgrade to agentic AI SOC](https://www.elastic.co/security-labs/blog/why-2026-is-the-year-to-upgrade-to-an-agentic-ai-soc) /
  [Intezer: Agentic SOC explained](https://intezer.com/guides/ai-soc/agentic-soc-explained) /
  [Splunk: 2026 security predictions](https://www.splunk.com/en_us/blog/leadership/security-predictions-2026-what-agentic-ai-means-for-the-people-running-the-soc.html)。

**本プロジェクトへの影響。** 本ノードの **完全な `reason[]`(0寄与・`applicable:false` も明示)・7要素タプルの
バイト同一リプレイ・監査チェーン(F-12/F-17 のフェイルクローズド)・助言専用**は、市場が**今まさに要件化している
性質そのもの**である。「LLM 推論 + 決定論フォレンジック = 監査対応エビデンス」という Intezer 型ハイブリッドは、
本ノードの「**LLM は説明・レポート生成に限定し、判定には使わない**」(Non-goals / ADR-0009)という既決教義の
ハイブリッド版に等しい。→ **中核変更は不要**。この整合は `docs/architecture.md` の失敗モデル節または
`docs/scoring.md` の論拠節に**外部追認として引用できる**(§4 P4)。

### 3.2 【据え置き確認】EPSS v5 のまま / ATT&CK v19.2(v20 未登場)/ STIX・TAXII 2.1 現行

- **EPSS**: **v5(2026-05-13 発表)が依然最新**。v5.x へのバンプは確認できず。318,000+ CVE をスコアし、
  v4 比 ~23% 改善の主張は不変。EPSS は依然 FIRST EPSS の **ML モデル**(本ノードは**外部計算済みスナップショットの
  取り込み**に限る)。
- **ATT&CK**: v19(2026-04-28)→ **v19.2(2026-08-05)** が最新。**v20 は未発表**。ただし **ATT&CKcon 7.0 が
  2026-10 開催**で、v20 の方向性が示される可能性がある。
- **STIX/TAXII**: **2.1 が OASIS 唯一の現行標準**。2.2 の committee spec / working draft は見当たらず。
- 出典: [Empirical Security: EPSS v5](https://natlawreview.com/press-releases/empirical-security-releases-epss-v5) /
  [ATT&CK バージョン履歴](https://attack.mitre.org/resources/versions/) / [ATT&CKcon 7.0(2026-10)](https://attack.mitre.org/resources/attackcon/october-2026/) /
  [OASIS CTI TC](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=cti) / [STIX/TAXII 2.1 OASIS 標準](https://www.oasis-open.org/2021/07/14/new-versions-of-stix-and-taxii-approved-as-oasis-standards-to-enable-automated-exchange-of-cyber-threat-intelligence/)。

**本プロジェクトへの影響。**
- **9月 P1(EPSS モデル版の世代固定)は解決済み。** 現行 [ADR-0014](../adr/0014-epss-advisory-ingest.md) は、
  EPSS 日次スナップショットのヘッダ `#model_version=…,score_date=…` を provenance として読み、
  **`epss_generation = hash(score_date, model_version, source digest)`** とし、「**全行が特定の EPSS モデル版・
  スコア日に辿れる**」設計になっている。しかも `epss_generation` は**スコアリング7要素タプルの外**に置かれ、
  EPSS 値の世代スワップが `raw_confidence`/`reason[]` のリプレイを**壊さない**。これは9月 P1 が求めた
  「モデル版を as-of の一部にする」を満たし、むしろ 7-tuple 非混入でより安全。→ **追加作業なし**。
- **9月 P2(ATT&CK v19 内容移行点検)は継続・未着手。** 外部版は v19.x のままで動いていないため、Defense Evasion
  分割(TA0005→Stealth / TA0112=Defense Impairment)に対する**内容移行点検の必要性は変わらず有効**。
  `docs/` に TA0112/Stealth への移行棚卸しの痕跡は無く、未着手のまま。→ §4 P3 として再掲し、**ATT&CKcon 7.0 の
  v20 動向を watch** に追加。
- **STIX/TAXII 2.1 据え置き**で ADR-0002/0005 は陳腐化せず、追随不要。

### 3.3 KEV 主・リスクベース優先度が連邦実装フェーズへ(BOD 26-04 の期限が稼働)

- **CISA BOD 26-04**(2026-06-10): 純 CVSS 依存を廃し、**Asset Exposure / KEV Status / Exploit Automation /
  Post-Exploitation Technical Impact** の4基準。**agency policy 更新期限 = 2026-08-07**、**新タイムラインの完全運用 =
  2026-12-07**。KEV カタログは継続的に追加(例: 2026-09-22, 09-29)。
- 出典: [CISA: BOD 26-04 新ディレクティブ](https://www.cisa.gov/news-events/news/cisa-issues-new-directive-improving-how-federal-agencies-prioritize-mitigation-cyber-vulnerabilities) /
  [SecurityWeek: リスクベース優先度](https://www.securityweek.com/cisa-directs-federal-agencies-to-prioritize-security-patches-based-on-risk/amp/) /
  [CISA KEV カタログ](https://www.cisa.gov/known-exploited-vulnerabilities-catalog/reducing-significant-risk-known-exploited-vulnerabilities)。

**本プロジェクトへの影響。** 本ノードの既存設計——**`cve_exploited`(KEV 由来, 重み 0.15, `applies_when:[eve_alert]`)を
確定事実として主に据え、EPSS は副次コンテキスト止まり**(ADR-0014)——は、BOD 26-04 の「**KEV 主・リスクベース**」を
先取りしている。9月時点では「連邦標準化」だったものが、**2026-12-07 の完全運用期限で連邦の実装フェーズに入る**——
KEV-primary 設計の時宜性が増した。KEV/SSVC は決定論ルックアップ/決定木、ML は EPSS **内部にのみ**閉じる構図は
決定論方針と両立。→ **中核変更不要**。追認引用のみ(§4 P4)。

### 3.4 行動 CTI(IOC→TTP)と予測型 CTI の潮流継続 + AI 悪用という新攻撃面

- **静的 IOC(IP/ハッシュ)→ TTP ベース**への移行が継続(TTP は長寿命でローテーションされにくい)。CTI は
  「記述型」から **「予測型(次に何をするか推定)」** へ向かうとされる。
- **攻撃側の AI 悪用**が観測事実に: 資格情報窃取 **QUIETVAULT** が侵害環境内で **local AI の CLI ツールを探し、
  定義済みプロンプトを実行**して設定ファイルを探索。「cyber criminal は速度を、espionage は極端な永続性を最適化」。
- 出典: [M-Trends 2026](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026) /
  [Trellix SecondSight(2026-09)](https://www.trellix.com/advanced-research-center/threat-reports/secondsight-threat-hunting-report-september-2026/) /
  [Cyware: proactive AI CTI 2026](https://www.cyware.com/blog/2026-the-year-when-cyber-threat-intelligence-evolves-into-proactive-ai)。

**本プロジェクトへの影響。二面性は9月と同じ。**
(i) **行動を軸に脅威を特徴づける方向**は Phase 2 Behavioral CTI と合致し、産業の主流化が追い風。
(ii) ただし商用の予測型 CTI の**手段**(ML/embedding/予測)は本ノードが**意図的に採らない**(ADR-0009)——
説明可能性・検証可能性の担保がその対価であり、§3.1 の市場要件がこの選択を正当化する。
(iii) **AI 悪用(prompt 実行型マルウェア QUIETVAULT)の台頭**は、本ノードが**最終権限を prompt 操作不能な
決定論アービタ(Azazel-Edge)に置き、CTI は助言データのみを返す**という教義を**さらに正当化**する。
→ **中核を動かす提案は不要**。§5 で「現行維持」。

---

## (4) 優先度付きアップデート提案

各項目: **提案 / 根拠+出典 / 想定工数 / リスク / 絶対制約との整合性**。すべてマスター判断待ち。
今月は**開発基盤層の二重世代バンプに直結する生モノ更新(P1)と、Claude Code 新機能への委任プロトコル整合(P2)**が
最優先。いずれも中核契約を動かさない。プロダクト層は**継続点検(P3)と追認引用(P4)**、保守衛生(P5)のみ。

### P1(高・低コスト・新規): 生モノ単一情報源の最新推奨世代を Opus 5.5 / GPT-6 に確定

- **提案**: `development-guide.md` §0 が「最新の推奨世代は本レポート最新号を単一情報源とする」としているとおり、
  本号(2026-10)をもって **Claude 側 = Opus 5.5、Codex 側 = GPT-6(既定、Sol/Luna/Astra から選択)** を確定値とする。
  他文書(CLAUDE.md / AGENTS.md / development-guide 本文)には世代名を**直書きしない**原則を再確認。実装・設定変更なし
  (GPT-6 は Codex 既定として自動適用、Opus 5.5 は Claude Code 既定)。
- **根拠+出典**: [Opus 5.5(2026-09-22)](https://9to5mac.com/2026/09/22/anthropic-upgrades-claude-with-new-opus-5-5-model-details-here/) /
  [GPT-6 Sol/Luna(2026-09-22)](https://9to5mac.com/2026/09/22/openai-upgrading-chatgpt-and-codex-with-two-more-gpt-6-models/) /
  [Codex changelog](https://developers.openai.com/codex/changelog)。
- **想定工数**: 0.1 人日(本レポートの確定記述のみ。他文書は参照方式なので修正不要)。
- **リスク**: 低。むしろ**直書きしていた場合に生じる3文書同時改訂と取りこぼし**を回避できる(de-hardcode 原則の効用)。
- **絶対制約整合性**: 抵触なし(モデル供給側の生モノ。スコアリング・依存・ランタイムに触れない)。

### P2(中・低コスト・新規): 委任プロトコルを Claude Code 新機能(AGENTS.md 直読み / sandbox strictAllowlist / Agent Teams)と整合

- **提案**: (a) **AGENTS.md 直読み**を受けて、`development-guide.md` §3 に「CLAUDE.md(指揮官規範)と AGENTS.md
  (実装者規範)は**両方とも Claude Code に自動で読まれる**」前提を一行注記し、両ファイルの絶対制約1〜8・テスト基準線・
  git 規律の記述に矛盾がないかを点検する短タスクを起票。(b) 指揮官セッションで **`sandbox.network.strictAllowlist` を
  既定 ON**(+必要ホストのみ `allowed_domains`)とする採用可否を §2B/§2C に注記——§2B 規約4(オフライン実装)・§2C
  (許可リスト運用)を Claude Code 機構で二重化。(c) §2C の MCP 衛生記述を微更新(**OAuth/OIDC 整合・stateless core**を
  語彙に追加)。(d) §2B 末尾の「native subagents 置換評価」注記に、**Agent Teams(coordinated subagents + messaging、
  depth 3)の登場で機構的相似がさらに強まった**旨を追記(置換はなお §5 の評価タスク)。
- **根拠+出典**: [Claude Code 新機能(9月)](https://releasebot.io/updates/anthropic/claude-code) /
  [Claude Code changelog](https://www.gradually.ai/en/changelogs/claude-code/) /
  [MCP 2026-07-28 仕様](https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/)。
- **想定工数**: 0.5〜0.75 人日(点検 + 文書注記。`strictAllowlist` の実採用は設定変更のみで別途)。
- **リスク**: 低。未整合のまま AGENTS.md 直読みが効くと、二重規範のズレを Claude Code が黙って拾う恐れ。
- **絶対制約整合性**: 抵触なし。④オフラインファースト・⑦依存最小性の精神を開発工程側へ延長。プロダクトへの MCP
  導入は**しない**方針を再掲。

### P3(高・低コスト・継続): ATT&CK v19 内容移行点検(9月 P2 の再掲)+ ATT&CKcon 7.0 で v20 watch

- **提案**: 9月 P2 で起票を促した「旧 TA0005(Defense Evasion)セマンティクスに依存する内容の棚卸し短報」は未着手。
  外部版が v19.x のまま動いていないため**依然有効**。`attack/` マッピング・`correlate/` 相関ルール・advisory テンプレート・
  docs 内の戦術名参照について、TA0005→Stealth 改称 / impairment 系の **TA0112(Defense Impairment)** 移動を一覧化し、
  世代更新時の移行手順を定める。加えて **ATT&CKcon 7.0(2026-10)を v20 の前触れとして watch** し、v20 公開前に点検を
  済ませておく。**リプレイ整合は `attack_version` 固定で既に保護**されるため、これは**内容移行**の点検であって
  決定論規律の変更ではない。
- **根拠+出典**: [ATT&CK バージョン履歴(v19.2 = 2026-08-05)](https://attack.mitre.org/resources/versions/) /
  [ATT&CKcon 7.0(2026-10)](https://attack.mitre.org/resources/attackcon/october-2026/) /
  [ATT&CK v19 updates(2026-04)](https://attack.mitre.org/resources/updates/updates-april-2026/)。
- **想定工数**: 点検短報 1 人日。実際の v20/v19 移行(採用時)は棚卸し結果次第で別 PR。
- **リスク**: 中。点検なしに世代を上げると、旧 TA0005 前提の advisory 出力が**意味的にずれる**。`attack_version` 固定が
  バイト同一リプレイは守るが、**内容の正しさ**は自動では守られない。点検止まりならリスクは低。
- **絶対制約整合性**: 抵触なし。②決定論(`attack_version` は既に7要素タプルの一員)・⑤local.db 不可侵(intel-tier の
  full-replace アダプタ経由、local-tier 非破壊)を維持。

### P4(低・最小コスト・追認引用): agentic SOC 説明可能性要件・決定論フォレンジック併用・BOD 26-04 稼働を論拠に反映

- **提案**: `docs/architecture.md` の失敗モデル節または `docs/scoring.md`/ADR-0009 の論拠節に、**(i)** 2026 の agentic SOC
  市場が「透明・説明可能・監査可能」「全判断に traceable reasoning」を要件化し、Intezer 型の「**LLM 推論 + 決定論
  フォレンジック = 再現可能・監査対応エビデンス**」が潮流であること、**(ii)** CISA BOD 26-04 の KEV 主・リスクベース
  優先度が **2026-12-07 完全運用**で連邦実装フェーズに入ること、を**既存設計の外部追認**として1〜2文引用する。
  設計変更は伴わない(引用のみ)。
- **根拠+出典**: [Intezer: agentic SOC](https://intezer.com/guides/ai-soc/agentic-soc-explained) /
  [Elastic: agentic AI SOC 2026](https://www.elastic.co/security-labs/blog/why-2026-is-the-year-to-upgrade-to-an-agentic-ai-soc) /
  [CISA BOD 26-04](https://www.cisa.gov/news-events/news/cisa-issues-new-directive-improving-how-federal-agencies-prioritize-mitigation-cyber-vulnerabilities)。
- **想定工数**: 0.25 人日(文書のみ)。
- **リスク**: 低。
- **絶対制約整合性**: 抵触なし(論拠補強のみ。重み表・タプル・契約に触れない)。

### P5(中・低コスト・継続): README の基準線テスト数(583)を単一情報源参照へ(9月 P3 の再掲、乖離拡大)

- **提案**: `README.md`(現在「currently 583 tests」)は、単一情報源である CLAUDE.md / `development-guide.md` §0 の
  **現行基準線(1213)と大きく乖離**している(9月号 P3 の時点では §0=591 だったが、以後 1213 まで動き、README だけ
  取り残された)。README を**具体数の直書きから、単一情報源を参照する表現へ改める**提案を再掲する。※ 実際の現行本数は
  単一情報源(`python -m pytest tests/unit -q` 実測)を正とし、本レポートでは値を確定させない。
- **根拠+出典**: 内部保守衛生(8月 P1 / 9月 P3 の de-hardcode 方針の未完部分)。外部トレンドではなく陳腐化点検として計上。
- **想定工数**: 0.25 人日(文書のみ)。
- **リスク**: 低。乖離を放置すると新規読者が古い基準線(583)を信じる。乖離が大きいほど害も大きい。
- **絶対制約整合性**: 抵触なし(文書表現の整合。ランタイム・スコアリング・依存に触れない)。

---

## (5) 据え置き・非推奨と判断した項目とその理由

| 項目 | 判断 | 理由 |
|---|---|---|
| **中核教義(助言専用・決定論・オフライン・非属性・LLM は説明のみ)の変更** | 現行維持 | agentic SOC 市場が「透明・説明可能・監査可能」を要件化([Elastic](https://www.elastic.co/security-labs/blog/why-2026-is-the-year-to-upgrade-to-an-agentic-ai-soc))、Intezer 型「LLM 推論 + 決定論フォレンジック = 監査対応エビデンス」([Intezer](https://intezer.com/guides/ai-soc/agentic-soc-explained))、BOD 26-04 の KEV 主実装フェーズ、AI 悪用マルウェア(QUIETVAULT)——**すべて教義を追認**。動かす動機なし。 |
| **EPSS を主指標化 / `threat_score` へ混入** | **非推奨** | EPSS は ML 由来の日次確率値。7要素タプルに入れると F-2/F-8(byte-identical replay)を破壊、ADR-0006 改訂が必要。ADR-0014 が副次限定・`epss_generation` を 7-tuple 外に置く形で foreclose 済み。EPSS v5 のまま値も安定。 |
| **ML/embedding/LLM ベースの behavioral scoring 採用** | **非推奨** | ADR-0009 が生成・類似度・スコアリングでの ML/embedding/clustering/LLM を明示禁止。市場の予測型 CTI は ML だが説明可能性が未解決の痛点——決定論選択が検証可能性で正当化される。**覆すなら shadow-only 節を超える新 ADR が必須**。 |
| **プロダクトへの MCP 導入 / 助言 API の MCP サーバ公開** | 据え置き | 仕様は 2026-07-28 で成熟(stateless core)だが、**MCP Apps(server-rendered UI)で攻撃面がさらに増える**。offline-first・依存最小性・助言専用に照らし価値対リスク過大。将来議論なら ADR 案件。開発工程側 §2C の衛生更新は別物(P2c)。 |
| **Claude Code ネイティブ subagents(Agent Teams)で Codex を置換** | 据え置き(評価タスク化) | Agent Teams(coordinated subagents + messaging、depth 3)は Option B の機構的相似をさらに強めたが、**別ベンダ併用の敵対的多様性**(写経レビュー回避)を失う。GPT-6・Opus 5.5 とも**フロンティア**で能力勾配は決め手にならず、拙速な置換をむしろ戒める。§2B 注記どおり ADR 相当の別タスクで評価([Claude Code changelog](https://www.gradually.ai/en/changelogs/claude-code/))。 |
| **Codex の使用モデル切替対応** | 対応不要 | GPT-6(Sol/Luna/Astra)は Codex 既定として自動適用。指示書は世代名を §0 単一情報源に委譲済みで、直書き修正は不要(P1 で確定)。 |
| **STIX 2.2 / TAXII 2.2 への追随** | 現行維持 | 2.2 は未公表、STIX/TAXII 2.1 が OASIS 唯一の現行標準([OASIS CTI TC](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=cti))。ADR-0002/0005 は陳腐化せず。 |
| **ATT&CK v20 への先行追随** | 据え置き(watch) | v20 は未発表(現行 v19.2 = 2026-08-05)。ATT&CKcon 7.0(2026-10)が前触れになりうるため watch。先行する前に P3 の v19 内容移行点検を済ませる。 |
| **NIST LEV の取込** | 据え置き(将来候補) | 9月号の判断(LEV は EPSS 時系列上の純粋演算で決定論親和だが、依然 NIST 提案・フィード非存在)を踏襲。本月は新事実の再確認をしておらず、[9月号 §5](ai-landscape-2026-09.md) の結論を据え置く。採用時も「副次・as-of 固定」の枠内に限る。 |
| **SQLite → PostgreSQL 移行** | 据え置き | ADR-0003 の移行トリガ(実測書込負荷)が未達。Pi 4 budget 内は SQLite WAL 継続が妥当。 |

---

## 付記: 陳腐化点検の総括(2026-10)

- **教義は10月時点でも陳腐化しておらず、agentic SOC の「説明可能・監査可能」要件化・決定論フォレンジック併用の
  潮流・BOD 26-04 の実装フェーズ入り・AI 悪用マルウェアの台頭に、むしろ強く追認されている。** 中核を動かす提案はない。
- **今月の主アクションは開発基盤層の生モノ更新2件**——**P1(Opus 5.5 / GPT-6 の世代確定、9月末の二重バンプ)**と
  **P2(Claude Code の AGENTS.md 直読み / sandbox strictAllowlist / Agent Teams への委任プロトコル整合)**。いずれも
  中核契約に触れない。
- **プロダクト層の外部版は据え置き**(EPSS v5・ATT&CK v19.2・STIX/TAXII 2.1)。**9月 P1(EPSS モデル版固定)は
  ADR-0014 の `epss_generation` に反映済みで解決**。P3(ATT&CK v19 内容移行点検)と P5(README 基準線整合)は継続。
- **MCP は本プロジェクトのランタイムに無関係**(MCP Apps で攻撃面が増える点が非導入判断を追認、開発工程側 §2C を微更新)。
- **ATT&CKcon 7.0(2026-10)を v20 の watch 項目**として記録。

### 参照一覧(主要出典)

- Claude モデル(Opus 5.5 / lineup): <https://9to5mac.com/2026/09/22/anthropic-upgrades-claude-with-new-opus-5-5-model-details-here/> / <https://www.anthropic.com/news/claude-opus-5> / <https://claudefa.st/blog/models>
- OpenAI Codex / GPT-6(Sol/Luna/Astra): <https://9to5mac.com/2026/09/22/openai-upgrading-chatgpt-and-codex-with-two-more-gpt-6-models/> / <https://developers.openai.com/codex/changelog> / <https://www.morphllm.com/best-ai-coding-agents-2026>
- Claude Code 新機能(Agent Teams / AGENTS.md 直読み / sandbox strictAllowlist): <https://releasebot.io/updates/anthropic/claude-code> / <https://www.gradually.ai/en/changelogs/claude-code/> / <https://code.claude.com/docs/en/whats-new>
- MCP(ロードマップ / 2026-07-28 stateless core / エコシステム): <https://blog.modelcontextprotocol.io/posts/mcp-roadmap/> / <https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/> / <https://workos.com/blog/everything-your-team-needs-to-know-about-mcp-in-2026>
- agentic SOC / 説明可能性 / 決定論フォレンジック: <https://www.elastic.co/security-labs/blog/why-2026-is-the-year-to-upgrade-to-an-agentic-ai-soc> / <https://intezer.com/guides/ai-soc/agentic-soc-explained> / <https://www.splunk.com/en_us/blog/leadership/security-predictions-2026-what-agentic-ai-means-for-the-people-running-the-soc.html>
- EPSS v5: <https://natlawreview.com/press-releases/empirical-security-releases-epss-v5> / <https://en.wikipedia.org/wiki/Exploit_Prediction_Scoring_System>
- MITRE ATT&CK(v19.2 / ATT&CKcon 7.0): <https://attack.mitre.org/resources/versions/> / <https://attack.mitre.org/resources/attackcon/october-2026/> / <https://attack.mitre.org/resources/updates/updates-april-2026/>
- KEV 主・リスクベース優先度(CISA BOD 26-04): <https://www.cisa.gov/news-events/news/cisa-issues-new-directive-improving-how-federal-agencies-prioritize-mitigation-cyber-vulnerabilities> / <https://www.securityweek.com/cisa-directs-federal-agencies-to-prioritize-security-patches-based-on-risk/amp/>
- 行動 CTI / 予測型 CTI / AI 悪用(M-Trends / Trellix / Cyware): <https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026> / <https://www.trellix.com/advanced-research-center/threat-reports/secondsight-threat-hunting-report-september-2026/> / <https://www.cyware.com/blog/2026-the-year-when-cyber-threat-intelligence-evolves-into-proactive-ai>
- OASIS STIX/TAXII 2.1: <https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=cti> / <https://www.oasis-open.org/2021/07/14/new-versions-of-stix-and-taxii-approved-as-oasis-standards-to-enable-automated-exchange-of-cyber-threat-intelligence/>
</content>
</invoke>
