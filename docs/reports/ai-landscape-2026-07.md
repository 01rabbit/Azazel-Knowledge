# 技術偵察レポート — AI・関連技術情勢と Azazel-CTI 陳腐化点検(2026-07)

作成日: 2026-07-08 / 担当: Claude Code(技術偵察) / 対象 main: PR #46 マージ後(583テスト基準線)

> **位置づけ。** 本レポートは**提案のみ**であり、コード・設計・ADR を一切変更しない。
> 各提案は CLAUDE.md 絶対制約1〜8(助言専用・決定論スコアリング・決定論入力規律・
> オフラインファースト・local.db 不可侵・フェイルクローズド・依存最小性・助言ルールのみ)
> と ADR-0001〜0009 を**尊重する**。教義に反する案は「非推奨」と明記し、覆すなら
> 新 ADR が要る旨を添えた(§5)。採否の最終判断はマスターに委ねる。

---

## (1) 要約(3行)

1. **Azazel-CTI の中核教義は陳腐化していない。** むしろ 2026 年の業界潮流(SANS 2026 CTI 調査:
   AI は要約・レポート用途に留まり human-in-the-loop が維持、STIX/TAXII は 2.1 のまま現行)は
   「決定論・助言専用・LLM は説明のみ」という既決方針を**追認**する方向に動いている。
2. **開発基盤層は世代交代が速い。** 現行フロンティアは Claude Opus 4.8(2026-05)/ OpenAI
   GPT-5.5(2026-04)。開発指示書 §2B が前提とする「Claude Code 指揮 × Codex 実装」の骨格は
   有効だが、モデル名・Claude Code の新機能(dynamic workflows / ネイティブ subagents)への
   追随と、MCP 供給網リスクへの目配りが必要。
3. **プロダクト層で検討価値のある追加は限定的だが実在する。** 最有力は **EPSS を
   オフライン・決定論の枠内で助言シグナル化**する案(既存 KEV 依存の自然な拡張)。それ以外は
   現行維持または非推奨で据え置き妥当。

---

## (2) 開発基盤層の新動向と本プロジェクトへの影響

### 2.1 フロンティアモデルの世代

| 項目 | 現況(2026-07 時点) | 出典 |
|---|---|---|
| Anthropic | **Claude Opus 4.8**(2026-05-28 リリース、Opus 4.7 の 41 日後)。同価格($5/$25 per Mtok)で agentic coding 64.3→69.2% 等を改善 | [Anthropic](https://www.anthropic.com/news/claude-opus-4-8) / [TechCrunch 2026-05-28](https://techcrunch.com/2026/05/28/anthropic-releases-opus-4-8-with-new-dynamic-workflow-tool/) |
| OpenAI | **GPT-5.5 / GPT-5.5 Pro**(API は 2026-04-24)。Terminal-Bench 2.0 82.7%、SWE-Bench Pro 58.6%。Codex は GPT-5.3-Codex→5.4→5.5 と進行、5.5 は 5.4 比で出力トークン約 40% 減 | [OpenAI GPT-5.5](https://openai.com/index/introducing-gpt-5-5/) / [Codex Changelog](https://developers.openai.com/codex/changelog) |

**本プロジェクトへの影響。** `docs/development-guide.md` §2B は「Claude Code(指揮)× OpenAI Codex
(実装)を worktree 分離で回す」体制を規定する。この**二社フロンティア併用による敵対的多様性**は
今も有効な設計判断であり、モデルが世代交代しても骨格は変わらない。一方で指示書内のモデル参照
(`--model <codex-model>` プレースホルダ)や「583テスト」等の数値は生モノなので、追随を怠ると陳腐化する。

### 2.2 Claude Code の新機能(dynamic workflows / subagents / plugins)

- Opus 4.8 と同時に **Dynamic Workflows**(research preview)が投入され、リード agent が
  数十〜数百の並列 subagent をファンアウトして「コードベース規模の移行を既存テストスイートを
  合否基準に kickoff→merge まで」回せるとされる([TechCrunch](https://techcrunch.com/2026/05/28/anthropic-releases-opus-4-8-with-new-dynamic-workflow-tool/))。
- subagent は既定でバックグラウンド実行、plugins は skills / hooks / subagents / MCP servers を
  1 インストール単位に束ねる包装層([Claude Code 機能一覧](https://code.claude.com/docs/en/features-overview))。

**本プロジェクトへの影響。** これは「Codex を外部実装者として使う Option B」の**代替候補**を生む
——Claude Code ネイティブの subagents で実装も回せる。ただし現行指示書が **OpenAI Codex を
別ベンダとして併用**するのは「指揮官と実装者を別モデルにして写経レビューを避ける」意図的な
敵対的多様性であり、単純な機能置換で捨てるべきではない。→ §4 P1 で「評価タスクとして記録、
即時変更はしない」提案に留める。

### 2.3 MCP エコシステムと供給網リスク

- MCP 公式レジストリは 2026-05-24 時点で最新サーバ 9,652 / バージョン 28,959 件、SDK 月間
  DL 9,700 万。2026 ロードマップはステートレス化・`.well-known` メタデータ・OAuth/OIDC 整合の
  Enterprise 認可を推進([MCP 2026 Roadmap](https://blog.modelcontextprotocol.io/posts/2026-mcp-roadmap/) / [WorkOS](https://workos.com/blog/everything-your-team-needs-to-know-about-mcp-in-2026))。
- **セキュリティは要警戒。** OX Security(2026-04)は Anthropic 公式 MCP SDK(Python/TS/Java/Rust)
  のコマンド実行脆弱性を報告、CVE-2025-6514(mcp-remote、DL 43.7 万)は悪性エンドポイントからの
  RCE を示した。実装の 82% にパストラバーサル、OAuth 採用は 8.5% のみ([OX Security](https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem/) / [Practical DevSecOps](https://www.practical-devsecops.com/mcp-security-vulnerabilities/))。

**本プロジェクトへの影響。** Azazel-CTI の**ランタイムは MCP を使わない**(コア依存は stdlib +
PyYAML + idna + PyNaCl のみ)。MCP はあくまで**開発ツールチェーン側**(Claude Code のツール接続)に
存在しうる。したがってプロダクトの攻撃面は増えていないが、(a) 開発時に外部 MCP サーバを
繋ぐ場合の供給網衛生、(b) 将来「助言 API を MCP サーバとして公開」する誘惑への線引き、の
2 点を方針として明文化する価値がある(§4 P4 / §5)。

---

## (3) プロダクト設計層の新動向と本プロジェクトへの影響

### 3.1 CTI 業界潮流 — AI 化と human-in-the-loop の均衡

- **SANS 2026 CTI 調査**: AI を使う CTI 組織は 45%、用途はデータ要約・レポート作成(56%)、
  パース/正規化(46%)、ワークフロー自動化(45%)が中心。**human-in-the-loop は堅持**され、
  高リスク判断はアナリスト監督が必須という回答が一貫。security operations が最上位ユースケース
  (71%)に復帰([SANS Institute](https://www.sans.org/white-papers/2026-sans-cyber-threat-intelligence-survey-insights) / [SOCRadar 要約](https://socradar.io/blog/2026-sans-cti-survey-report-findings/))。
- 一方で商用 CTI プラットフォームは **ML ベースの behavioral scoring / 予測相関**(IoC×IoA を
  リアルタイム相関、重大度を ML でランク付け)を前面に出す潮流([Stellar Cyber](https://stellarcyber.ai/learn/top-cyber-threat-intelligence-cti-platforms/) / [Informatix](https://informatix.systems/blog/cyber-threat-intelligence-services/predictive-threat-intelligence-innovations-2026/))。

**本プロジェクトへの影響。** ここに**二面性**がある。
(i) 「AI は説明・レポートに限定、判定は決定論、人間/決定論アービタが最終権限」という
Azazel の教義(README 非目標、roadmap 恒常制約、ADR-0006/0009)は SANS 調査の実務潮流に
**むしろ合致**しており、陳腐化していない——これは強い追認材料。
(ii) 商用が向かう「ML behavioral scoring」は Azazel が**意図的に採らない**方向(ADR-0009 は
生成・類似度・スコアリングに ML/embedding/clustering/LLM を禁止)。この乖離は弱みではなく
**差別化された研究姿勢**(ADR-0008「CTI 最適化された遅延防御」)として位置づけ直すのが妥当。
→ §5 で「ML 化は非推奨(覆すなら新 ADR)」と明記。

### 3.2 標準(STIX / TAXII)

- **STIX 2.1 / TAXII 2.1 が依然として現行の OASIS 標準**。STIX 2.2 の公表は確認できず(2021-06 公開の
  2.1 が最新)([OASIS STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html) / [OASIS CTI TC](https://oasis-open.github.io/cti-documentation/))。

**本プロジェクトへの影響。** ADR-0002/0005(「native モデル内部・STIX 2.1/TAXII 2.1 は境界のみ」)は
**現行標準に一致しており陳腐化していない**。バージョン追随の必要なし。→ §5 で「現行維持」。

### 3.3 脆弱性優先度付け(KEV / ATT&CK / EPSS)

- **EPSS**(FIRST 提供、悪用確率の予測モデル)は 2026 も脆弱性優先度付けの標準要素。ただし
  2026 研究で「EPSS の中央値の動きは KEV 掲載**後**が掲載前の 121 倍」= 先行指標としては遅れる
  という限界が指摘([Nucleus](https://nucleussec.com/blog/epss-score-is-predictive-but-late/) / [CrowdStrike](https://www.crowdstrike.com/en-us/cybersecurity-101/exposure-management/exploit-prediction-scoring-system-epss/))。
- **KEV×ATT&CK 充足率は低い**: KEV 1,488 件中 ATT&CK マッピングは 424 件のみ(最も疎な
  enrichment 次元)([runZero KEVology](https://www.runzero.com/resources/kevology/))。
- 推奨される優先度モデルは「KEV+高CVSS+高EPSS=緊急」「高EPSS+高CVSS+未KEV=先行的パッチ」
  といった多次元合成([isMalicious](https://ismalicious.com/posts/epss-exploit-prediction-scoring-system-patch-prioritization))。

**本プロジェクトへの影響。** Azazel のスコアリングは既に `cve_exploited`(KEV 由来)重みを持つ
(docs/scoring.md、重み 0.15)。**EPSS を追加の助言シグナル**として決定論・オフラインの枠内で
取り込む余地がある(§4 P2)。EPSS の「掲載後に動く」限界は、Azazel が予測ではなく**説明可能な
決定論**を旨とする以上、むしろ「確率でなく確定事実(KEV)を主、EPSS を副次コンテキスト」と
する扱いに整合する。

---

## (4) 優先度付きアップデート提案

各項目: **提案 / 根拠+出典 / 想定工数 / リスク / 絶対制約との整合性**。すべてマスター判断待ち。

### P1(高・低コスト): 開発指示書のモデル参照更新と Claude Code ネイティブ subagents の評価記録

- **提案**: `docs/development-guide.md` §2B のモデル参照を現行世代(例示として Codex 側
  GPT-5.5-Codex 系)に更新し、注記として「Claude Code の dynamic workflows / ネイティブ
  subagents は Option B の代替候補だが、**指揮官と実装者を別ベンダに分ける敵対的多様性**を
  失うため即時採用しない。評価は別タスクで行い、採否は ADR 相当の判断を要する」と明記する。
  併せて基準線テスト数(583)を可変値として1箇所参照に集約する運用注記を足す。
- **根拠+出典**: モデル世代交代([Opus 4.8](https://www.anthropic.com/news/claude-opus-4-8) / [GPT-5.5](https://openai.com/index/introducing-gpt-5-5/))、dynamic workflows([TechCrunch](https://techcrunch.com/2026/05/28/anthropic-releases-opus-4-8-with-new-dynamic-workflow-tool/))。
- **想定工数**: 0.5 人日(文書のみ、コード変更なし)。
- **リスク**: 低。文書追随の怠りが最大のリスクなので、むしろ着手の遅れが害。
- **絶対制約整合性**: 抵触なし(開発体制文書。ランタイム挙動・依存・スコアリングに触れない)。

### P2(中・中コスト): EPSS をオフライン・決定論の枠内で助言シグナル化する設計スパイク

- **提案**: EPSS スコアを**新規フィード adapter**(クエリパス外、worker/bundle 経由)として
  取り込み、`/v1/context` の助言に**副次コンテキスト**として付す設計スパイクを起こす。
  スコアリング本体の 7 要素決定論タプルには**入れず**(F-2/F-8 の byte-identical replay を
  破らない)、Phase 2 の behavioral lane と同様に**別の config 世代ハッシュ**下で
  「EPSS as-of 世代」を固定して決定論リプレイ可能にする。実装は**提案段階では行わない**——
  本レポートは設計スパイクの起票までを提案する。
- **根拠+出典**: EPSS の実務標準性と「予測だが遅れる」限界([Nucleus](https://nucleussec.com/blog/epss-score-is-predictive-but-late/) / [CrowdStrike](https://www.crowdstrike.com/en-us/cybersecurity-101/exposure-management/exploit-prediction-scoring-system-epss/))、多次元優先度モデル([isMalicious](https://ismalicious.com/posts/epss-exploit-prediction-scoring-system-patch-prioritization))。既存 `cve_exploited` 重みの自然な拡張。
- **想定工数**: 設計スパイク 1〜2 人日。実装(採用時)は adapter + 世代管理 + テストで 5〜8 人日相当。
- **リスク**: 中。(a) EPSS は日次更新の確率値 → **決定論とオフラインファーストの両立**が肝。
  as-of 世代固定と bundle 取込に徹すれば両立可能。(b) スコアリング本体に混ぜると F-2/F-8 を破る
  → 混ぜない設計が必須。(c) 新フィード = feeds/ の adapter 追加であり、コア依存追加は伴わない
  (HTTP 取得は既存の feed importer 経路)。
- **絶対制約整合性**: 満たせる設計が存在する。①助言専用: 副次コンテキストのみ、書込は worker 単一
  ライタ。②決定論: 別 config 世代ハッシュ + as-of 固定でリプレイ担保。④オフラインファースト:
  取得は worker/bundle、クエリパスに online 依存を足さない。⑦依存最小性: adapter は既存経路で
  新規 pip 依存なし。**ただしスコアリング本体の重み変更を伴う案なら ADR-0006 改訂が必要**——
  今回は「副次コンテキスト止まり(重み表を変えない)」を推奨。

### P3(中・低コスト): 依存とランタイムの陳腐化点検(Python / API 依存)

- **提案**: `pyproject.toml` の `requires-python = ">=3.11"` と、`api`/`dev` の未ピン依存
  (fastapi/pydantic/uvicorn/pytest/httpx)について、(a) サポート下限 Python の見直し、
  (b) メジャー固定の可否、(c) pydantic v2 系前提の明記、を点検する短報を起こす。**コア依存
  (stdlib+PyYAML+idna+PyNaCl)は変更しない**。
- **根拠+出典**: 一般的な保守衛生(本レポートは外部トレンドではなく内部陳腐化点検として計上)。
  Pi 4 の resource budget(architecture.md、< 2GB RSS)を壊さない範囲での更新に限る。
- **想定工数**: 0.5〜1 人日(点検短報のみ、依存追加はしない)。
- **リスク**: 低〜中。API 依存のメジャー更新は fastapi/pydantic の破壊的変更を招きうるため、
  点検に留め、更新自体は別 PR + テスト全緑を条件にする。
- **絶対制約整合性**: ⑦依存最小性を**強化する**方向。新規依存追加を伴わない限り抵触なし。

### P4(中・低コスト): 開発ツールチェーンの供給網衛生を方針化(MCP/エージェント)

- **提案**: `docs/development-guide.md` または新規短節に「開発時に外部 MCP サーバや
  エージェント拡張を接続する際の最小衛生」(信頼できるソースのみ、OAuth/権限最小化、
  ネットワーク要求の遮断、SDK バージョン追随)を明文化。**プロダクトへの MCP 導入は
  現時点で行わない**ことも同時に明記。
- **根拠+出典**: MCP 供給網 RCE と実装衛生の欠如([OX Security 2026-04](https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem/) / [Practical DevSecOps](https://www.practical-devsecops.com/mcp-security-vulnerabilities/) / [CSA](https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-security-crisis-20260504-csa-styled/))。プロンプトインジェクションが全体侵害ベクタ化。
- **想定工数**: 0.5 人日(文書のみ)。
- **リスク**: 低。むしろ未明文化のまま外部 MCP を繋ぐことがリスク。
- **絶対制約整合性**: 抵触なし。オフラインファースト/依存最小性の精神を開発工程側へ延長する。

---

## (5) 据え置き・非推奨と判断した項目とその理由

| 項目 | 判断 | 理由 |
|---|---|---|
| **STIX/TAXII のバージョン追随** | 現行維持 | STIX 2.1 / TAXII 2.1 が依然 OASIS 現行標準。2.2 は未公表。ADR-0002/0005 は陳腐化していない([OASIS](https://oasis-open.github.io/cti-documentation/))。 |
| **ML/embedding/LLM ベースの behavioral scoring 採用** | **非推奨** | ADR-0009 が生成・類似度・スコアリングでの ML/embedding/clustering/LLM を明示禁止。ADR-0006 の決定論・完全 `reason[]`・byte-identical replay と正面衝突する。商用潮流([Stellar Cyber](https://stellarcyber.ai/learn/top-cyber-threat-intelligence-cti-platforms/))はあるが、SANS 2026 は human-in-the-loop 堅持を示し教義を追認([SANS](https://www.sans.org/white-papers/2026-sans-cyber-threat-intelligence-survey-insights))。**覆すなら shadow-only 節を超越する新 ADR が必須**(ADR-0009 帰結節が明記)。 |
| **助言 API の MCP サーバ公開** | 据え置き | 攻撃面(プロンプトインジェクション/RCE 供給網)と依存増を招く。offline-first・依存最小性・助言専用の教義に照らし、価値に対しリスク過大。将来議論するなら ADR 案件。 |
| **SQLite → PostgreSQL 移行** | 据え置き | ADR-0003 の移行トリガ(実測書込負荷)が未達。roadmap Phase 2 の未計測項目。Pi 4 budget 内は SQLite WAL 継続が妥当。 |
| **LLM による判定(verdict)導入** | **非推奨** | README 非目標・roadmap 恒常制約が「LLM は説明/レポート生成に限定、verdict は決定論」と規定。SANS 2026 も同方向。教義の中核であり覆す動機なし。 |
| **予測型(EPSS を主指標化)スコアリング** | 非推奨(副次のみ可) | EPSS は「KEV 掲載後に動く」遅行性があり([Nucleus](https://nucleussec.com/blog/epss-score-is-predictive-but-late/))、確定事実(KEV)主・確率(EPSS)副次の決定論方針を主指標化で崩すべきでない。P2 は副次コンテキスト止まりに限定。 |

---

## 付記: 陳腐化点検の総括

- **教義(助言専用・決定論・オフラインファースト・非属性・LLM は説明のみ)は 2026-07 時点で
  陳腐化しておらず、業界潮流にむしろ追認されている。** 中核を動かす提案はない。
- **陳腐化が起きやすいのは「生モノ」= モデル名・テスト基準線・依存バージョン・開発ツール
  チェーンの前提**であり、P1/P3/P4 はその追随(いずれも文書 or 点検、コード非改変)。
- **唯一のプロダクト機能拡張候補は P2(EPSS 副次シグナル)**で、これも決定論・オフライン・
  依存最小の枠内に収まる設計が存在する。実装は本レポートの範囲外(設計スパイク起票まで)。

### 参照一覧(主要出典)

- Anthropic Claude Opus 4.8: <https://www.anthropic.com/news/claude-opus-4-8>
- TechCrunch, Opus 4.8 dynamic workflows(2026-05-28): <https://techcrunch.com/2026/05/28/anthropic-releases-opus-4-8-with-new-dynamic-workflow-tool/>
- OpenAI GPT-5.5: <https://openai.com/index/introducing-gpt-5-5/> / Codex Changelog: <https://developers.openai.com/codex/changelog>
- MCP 2026 Roadmap: <https://blog.modelcontextprotocol.io/posts/2026-mcp-roadmap/>
- OX Security, MCP 供給網 RCE(2026-04): <https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem/>
- SANS 2026 CTI Survey: <https://www.sans.org/white-papers/2026-sans-cyber-threat-intelligence-survey-insights>
- OASIS STIX 2.1 / CTI TC: <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html> / <https://oasis-open.github.io/cti-documentation/>
- EPSS 限界(Nucleus): <https://nucleussec.com/blog/epss-score-is-predictive-but-late/> / runZero KEVology: <https://www.runzero.com/resources/kevology/>
</content>
</invoke>
