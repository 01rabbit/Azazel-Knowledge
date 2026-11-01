# 技術偵察レポート — AI・関連技術情勢と Azazel-Knowledge 陳腐化点検(2026-11)

作成日: 2026-11-01 / 担当: Claude Code(技術偵察) / 対象 main: `09d234c`(Phase 1 + Phase 2 Behavioral CTI + AZ-06 deception effectiveness / Fabric api-extra pin `v0.9.0rc2` / ADR-0001〜0018 まで反映)

> **位置づけ。** 本レポートは**提案のみ**であり、コード・設計・ADR を一切変更しない。
> 各提案は CLAUDE.md 絶対制約1〜8(助言専用・決定論スコアリング・決定論入力規律・
> オフラインファースト・local.db 不可侵・フェイルクローズド・依存最小性・助言ルールのみ)と
> ADR-0001〜0018 を**尊重する**。教義に反する案は「非推奨」と明記し、覆すなら新 ADR が
> 要る旨を添えた(§5)。採否の最終判断はマスターに委ねる。
>
> **前月からの継続。** 本書は [`ai-landscape-2026-10.md`](ai-landscape-2026-10.md) の後継。
> 10月レポートの結論(中核教義は陳腐化せず、陳腐化は「生モノ」= モデル名・基準線・依存版・
> 外部データ版に集中)は11月も維持される。今月の2大事実は、**(a) 10月レポートが watch に
> 挙げた MITRE ATT&CK v20 が実際に出荷された(2026-10-13)**ことと、**(b) 開発基盤層の churn が
> 片側(Codex=GPT-6.1)に集中し、Claude 側は Opus 5.5 のまま据え置かれた**こと。前者は10月 P3
> (ATT&CK 内容移行点検)を「watch」から「着手可能」へ昇格させ、かつ v20 が **AI プロンプト
> インジェクションを TTP として正式収載**したことで中核教義を一段強く追認する。後者は生モノ
> 単一情報源の更新範囲を Codex 側だけに絞る。いずれも中核契約は動かさない。

---

## (1) 要約(3行)

1. **中核教義は11月時点でも陳腐化しておらず、外部追認はさらに強まった。** MITRE が **ATT&CK v20
   (2026-10-13)で Direct/Indirect Prompt Injection・AI-Enabled Exfiltration 等を TTP として正式収載**し、
   学術側も **TRACE-CTI(arXiv)が「モデルが予測したものと、システムが信頼してよいものの間に明示的・
   監査可能な境界が無い」ギャップ**を名指し——本ノードの「助言専用・完全な `reason[]`・provenance・
   最終権限はプロンプト操作不能な決定論アービタ(Azazel-Edge)」設計が、産業・学術双方の要件に合致。
2. **開発基盤層の churn は今月 Codex 側のみ。** Anthropic は **Opus 5.5 を据え置き**(9/22 以降新世代なし、
   Sonnet/Haiku 5.5 は未出荷)、OpenAI は Codex を **GPT-6(Sol/Luna/Astra)→ GPT-6.1(Sol 9/29・
   Terra 10/26、API は GPT-5.6 Terra 比 ~50% 安)**へ更新。生モノ単一情報源の更新は **Codex 側を GPT-6.1
   (既定 Terra)に確定するだけ**(§4 P1)。Claude Code は背景エージェントのドラフト PR 起票等を追加(§2.2)。
3. **プロダクト層の最重要事実は ATT&CK v20 出荷。** 10月 P3 の watch が現実化。(i) 繰越の v19 Defense
   Evasion 分割 + v20 内容を合わせた**移行点検が着手可能**になり、(ii) v20 の AI 系5技術を **intel-tier
   の追加助言コンテキストとしてマッピングする好機**が生まれた(§4 P2)。EPSS v5・STIX/TAXII 2.1 は据え置き。
   README 基準線(583)は単一情報源(1437)との**乖離がさらに拡大**(§4 P5)。

---

## (2) 開発基盤層の新動向と本プロジェクトへの影響

### 2.1 フロンティアモデル: churn は今月 Codex 側のみ(Claude=Opus 5.5 据え置き / Codex=GPT-6.1)

| ベンダ | 10月時点(前号) | 11月時点(本書) | 出典 |
|---|---|---|---|
| Anthropic | Opus 5.5(2026-09-22 GA) | **据え置き。Opus 5.5 のまま**(9/22 以降の新フロンティア世代なし)。Platform Docs は Opus 5.5 を active latest と表示(1M ctx / 128K 出力、$4/$20 per Mtok)。予告の **Sonnet 5.5 / Haiku 5.5 は本号時点で出荷未確認** | [Anthropic: Opus 5.5](https://www.anthropic.com/claude-opus-5-5) / [Platform Docs: Opus 5.5](https://platform.claude.com/docs/en/models/opus-5-5/overview) / [9to5Mac: Opus 5.5](https://9to5mac.com/2026/09/22/anthropic-upgrades-claude-with-new-opus-5-5-model-details-here/) |
| OpenAI | Codex 既定 = GPT-6 世代(Sol/Luna/Astra) | **GPT-6.1 世代へ。GPT-6.1 Sol(2026-09-29)**、**GPT-6.1 Terra(2026-10-26)が ChatGPT Work と Codex に展開**(高速・低コスト、coding/computer-use 強化、API は GPT-5.6 Terra 比 ~50% 安、`gpt-6.1-terra`)。Codex CLI 0.164.0 は再利用プロンプトプリセット・inline モデル/権限設定・enterprise MCP 認証拡張を追加 | [OpenAI: Model release notes](https://help.openai.com/en/articles/9624314-model-release-notes) / [Releasebot: OpenAI(10月)](https://releasebot.io/updates/openai) |

**本プロジェクトへの影響。**
(a) **生モノ churn は片側のみ**。10月は Claude・OpenAI が同日に揃って世代を上げたが、11月は **Claude 側が
Opus 5.5 で静止**し、**Codex 側だけが GPT-6.1(既定 Terra)へ進んだ**。これは `development-guide.md` §0 が
**最新推奨世代を本レポート最新号に単一情報源化**した判断の効用を改めて示す——直書きなら Codex 世代更新のたびに
複数文書を触るところ、本号で「**Claude=Opus 5.5(据え置き)/ Codex=GPT-6.1(既定 Terra)**」と確定するだけで済む(§4 P1)。
(b) 能力勾配は依然どちらも**フロンティア**で決定的差はない。よって「**指揮官・敵対的レビュー=Claude、実装労働=Codex**」の
分業(§2/§2B)は、能力差ではなく**別ベンダ併用による敵対的多様性**(写経レビュー回避)で正当化される——この論拠は
世代更新で変わらない(§5)。
(c) GPT-6.1 Terra の **API ~50% コスト減**は Option B(`codex exec` 配線)の実行経済を改善するが、教義・契約には無関係。

### 2.2 Claude Code: 背景エージェントのドラフト PR 起票 / Claude in Chrome GA / モデルフォールバック要約

- **背景エージェントがドラフト PR を開く**よう進化(本偵察タスク自体がこの形で駆動されている)。cloud routine に
  **effort-level ピッカー**、長時間タスク中の **keep-awake**、iOS Simulator 対応、再起動後のセッション窓復元を追加。
- **Claude in Chrome が GA**。小さいコンテキスト窓のモデルへ切替時、**旧モデルが会話を先に要約**してから渡す
  (コンテキスト溢れの事前回避)。auto モードのブロック通知がコマンド名と `/permissions` を明示。
- 出典: [Claude Code changelog](https://code.claude.com/docs/en/changelog) /
  [Claude Code Changelog(10月, gradually.ai)](https://www.gradually.ai/en/changelogs/claude-code/) /
  [changelogs.directory: claude code 2.1.312](https://changelogs.directory/tools/claude-code/releases/2.1.312)。

**本プロジェクトへの影響。**
(a) **背景エージェントのドラフト PR 起票**は、本リポの運用(偵察・保守の定期タスクをドラフト PR として提出)と
機構的に噛み合う。git 規律(PR はドラフト)と矛盾しない。追加作業不要。
(b) **Claude in Chrome GA** はブラウザ=ネットワーク面の拡張であり、オフラインファースト(絶対制約4)・
`sandbox.network.strictAllowlist`(10月 P2b で注記)の観点から、**指揮官セッションでのブラウザ機能はクエリパス検証に
使わない**規律を再確認する価値がある(プロダクトのクエリパスとは独立だが、開発工程の衛生として)。
(c) いずれも**中核契約に無関係**。10月 P2(委任プロトコル整合)の範囲内の微更新候補にとどまる。

### 2.3 MCP: stateless core(2026-07-28)で安定、Codex は enterprise MCP 認証を拡張

- MCP は 2026-07-28 仕様(stateless core + MCP Apps + Tasks + OAuth/OIDC 整合)のまま大きな新仕様なし。
  **Codex CLI 0.164.0 が enterprise MCP 認証を拡張**した程度(ツール側の DX 進展)。
- 出典: [Releasebot: OpenAI(Codex CLI 0.164.0)](https://releasebot.io/updates/openai)。

**本プロジェクトへの影響。** 10月から不変——**本ノードのランタイムは MCP を使わない**(コア依存は stdlib + PyYAML +
idna + PyNaCl、Fabric も `api`/`taxii` extra 限定)。Codex 側の MCP 認証拡張は開発工程(§2C)の語彙更新候補だが、
プロダクト導入とは別物。**非導入判断は維持**(§5)。

---

## (3) プロダクト設計層の新動向と本プロジェクトへの影響

### 3.1 【最重要・watch 現実化】MITRE ATT&CK v20 出荷(2026-10-13):AI プロンプトインジェクションを TTP として正式収載

- 10月 P3 が watch に挙げた **v20 が 2026-10-13 に出荷**(v19.2 を置換)。新規 Enterprise 技術9件のうち**5件が AI 系**:

  | 技術 | ID |
  |---|---|
  | Direct Prompt Injection | **T1699** |
  | Indirect Prompt Injection | **T1698** |
  | AI-Enabled Exfiltration | **T1700** |
  | AI Result Poisoning | **T1608.007** |
  | Impair Autonomous Defenses | **T1685.007** |

- 併せて **T1697 Steal Application Specific Passwords(MFA 迂回)**、**T1696 Anti-Automation Evasion(CAPTCHA 系)**、
  **T1195.001 が開発環境・AI コーディングエージェント設定ファイルを対象に大幅更新**。新規グループ2件
  (NIMBUS MANTICORE / The Gentlemen)、新規キャンペーン2件(C0066 米水道事業攻撃 / C0064 AI 支援メキシコ政府侵害)。
  規模: Software 971 / Groups 182 / Campaigns 61。
- 出典: [MITRE: ATT&CK v20(versions)](https://attack.mitre.org/versions/v20/) /
  [MITRE ATT&CK blog: v20](https://medium.com/mitre-attack/attack-v20-9701dd75ffb4) /
  [SecurityWeek: v20 catalogs AI abuse](https://www.securityweek.com/mitre-attck-v20-catalogs-ai-abuse-mfa-bypass-water-utility-attacks/) /
  [cybersecuritynews: v20 9 new techniques](https://cybersecuritynews.com/mitre-attck-v20-released/)。

**本プロジェクトへの影響。二面。**
(i) **教義の強い追認。** ATT&CK が**プロンプトインジェクションを正式な敵対者 TTP として収載**したことは、本ノードが
「**最終権限をプロンプト操作不能な決定論アービタ(Azazel-Edge)に置き、CTI は助言データのみ返す**」(README Non-goals /
ADR-0009)という教義を、権威ある脅威分類の裏付けで正当化する。LLM を**説明・レポート生成に限定し判定に使わない**設計は、
T1699/T1698 の攻撃面そのものを**プロダクトのクエリパスから排除**している。→ **中核変更は不要**。§3.1 を §4 P4 の追認引用に使える。
(ii) **新しい具体作業の好機。** 10月 P3 で「watch」としていた v20 が出た。これにより **2つの作業**が着手可能になる(→ §4 P2):
- **(ii-a) 内容移行点検(繰越 + 新規)**: 繰越の v19 Defense Evasion 分割(TA0005→Stealth / TA0112=Defense Impairment)の
  棚卸しに、**v19.2→v20 差分**を合算して一括点検する。`attack/` マッピング・`correlate/` 相関ルール・advisory テンプレート・
  docs の戦術/技術参照が対象。**リプレイ整合は `attack_version`(7要素タプルの一員)固定で既に保護**されるため、これは
  **内容移行**の点検であって決定論規律の変更ではない。
- **(ii-b) AI 系5技術の追加助言マッピング評価**: T1698/T1699/T1700/T1608.007/T1685.007 を **intel-tier の追加助言
  コンテキスト**として `attack/` に取り込む価値がある。本ノードが Azazel-Edge に「観測された事象が AI 悪用 TTP に対応し得る」旨を
  **助言データとして**返せれば、Edge の決定品質を高めうる。これは **intel-tier の full-replace アダプタ経由**(local.db 非破壊=
  絶対制約5)・**7要素タプル外**(`attack_version` 固定で決定論維持=絶対制約2/3)の**追加であり、助言専用(絶対制約1)を崩さない**。
  ただし「AI 悪用 TTP へのマッピング」は**非属性教義**(AI 使用の証明ではない)を踏み外さない文面規律が要る(ADR-0009)。

### 3.2 【学術側の強い追認】TRACE-CTI:抽出 TTP の「予測」と「信頼」の間に監査可能な境界を置く

- arXiv の **TRACE-CTI**(Auditable Post-Extraction Governance of TTP Claims with Knowledge Graphs)は、SOC パイプラインで
  「**モデルが抽出した ATT&CK マッピングが、明示的・監査可能な境界なしに信頼事実として扱われている**」ギャップを名指し、
  provenance と失効(revocation)を追跡するガバナンス層を提案(新しい抽出器でも特定 LLM 依存でもない)。
- 出典: [arXiv: TRACE-CTI](https://arxiv.org/pdf/2607.24563)。

**本プロジェクトへの影響。** TRACE-CTI が問題視する境界の欠如は、本ノードが**既に設計で解決**している論点である——
**完全な `reason[]`(0寄与・`applicable:false` も明示)/ 7要素タプルのバイト同一リプレイ / 監査チェーン(F-12/F-17 の
フェイルクローズド)/ 助言専用**は、「何を予測し、何を信頼し、なぜそう助言したか」を機械的に辿れる境界そのもの。→
**中核変更不要**。§4 P4 の追認引用に、10月の agentic SOC 実務要件(透明・説明可能・監査可能)と並べて学術的裏付けとして加える。

### 3.3 【据え置き確認】EPSS v5 のまま / STIX・TAXII 2.1 現行 / BOD 26-04 はリスクベース期日へ移行

- **EPSS**: **v5(model v2026.06.15, 2026-06-15 以降)が依然最新**。v5.x へのバンプは確認できず(FIRST の ML モデル、
  本ノードは**外部計算済みスナップショットの取り込み**に限る)。一部二次情報は v4 と古い記述が残るため一次情報を正とする。
- **STIX/TAXII**: **2.1 が OASIS 唯一の現行標準**。「STIX-2.2」は OASIS CTI TC の**未解決 GitHub issue 群(Q&A オブジェクト提案等)**に
  留まり、ballot / committee spec / リリース告知は見当たらない。
- **CISA BOD 26-04**(2026-06-10 発行): 固定期日モデルを廃し、**Asset Exposure / KEV Status / Exploit Automation /
  Technical Impact** の4変数で**脆弱性ごとに 3 / 14 / 60 日または次回更新へ繰延**を決める。最高リスク層(**KEV 掲載 + 完全制御**)は
  **3日以内に修復と並行してフォレンジック・トリアージ**を要求。agency policy 更新は 2026-08-07 が節目。
  ※ 10月レポートが記した「2026-12-07 完全運用」は本号の調査で一次確認できず、**期日は脆弱性ごとのタイムライン表に移行**した
  と理解するのが妥当(§5 で補正)。
- 出典: [Craci: EPSS v5(model v2026.06.15)](https://craci.com/epss) / [Parameter: EPSS](https://www.parameter.ai/learn/exploit-prediction-scoring-system) /
  [OASIS CTI TC](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=cti) /
  [oasis-tcs/cti-stix2 issues(STIX-2.2 tag)](https://github.com/oasis-tcs/cti-stix2/issues) /
  [CISA: BOD 26-04 実装ガイダンス](https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk) /
  [Tenable: BOD 26-04 FAQ](https://www.tenable.com/blog/cisa-bod-26-04-FAQ-vulnerability-remediation-impact)。

**本プロジェクトへの影響。**
- **EPSS / STIX/TAXII 据え置き**で ADR-0002/0005/0014 は陳腐化せず、追随不要。9月 P1(EPSS モデル版固定)は ADR-0014 の
  `epss_generation`(7要素タプル外)で**解決済み**、今月も再確認。
- **BOD 26-04 の KEV 主・リスクベース方向**は、本ノードの **`cve_exploited`(KEV 由来, 重み 0.15, `applies_when:[eve_alert]`)を
  主、EPSS は副次コンテキスト止まり**(ADR-0014)という既決設計を引き続き先取り。**KEV + 完全制御の3日フォレンジック要求**は、
  本ノードの「決定論・再現可能・監査可能なエビデンス生成」姿勢とさらに整合(forensic-ready = 監査チェーン + 完全な `reason[]`)。
  → **中核変更不要**。追認引用のみ(§4 P4)。

### 3.4 AI 悪用の継続・深化:自律エージェントによる資格情報大量窃取(DUSTMAKER)、AI 開発者設定が標的に

- Google **GTIG** 報告: ある脅威アクターがクラウド資源を侵害後、**エージェント駆動ワークフローで6時間未満の大量資格情報
  ハーベスト**を実行。**DUSTMAKER** 資格情報窃取マルウェアは、設定ファイルや JavaScript ローダのコメントに**プロンプトを埋め込み、
  LLM ベースのセキュリティスキャナを回避**しようとした。インフォスティーラ(Lumma/Vidar/ACR 等)が **AI 開発者設定を標的に拡張**。
- OWASP 2026(Help Net 経由): **プロンプトインジェクションがエージェント AI 失敗の中心**。LiteLLM の PyPI バックドア、Cursor の
  CVE-2026-22708(auto-approve された許可コマンドが配送経路化)も報告。
- 出典: [Google GTIG: From Prompting to Autonomy](https://cloud.google.com/blog/topics/threat-intelligence/from-prompting-to-autonomy-the-evolution-of-adversarial-ai) /
  [The Hacker News: autonomous AI agents compromise credentials](https://thehackernews.com/2026/09/autonomous-ai-agents-compromise.html) /
  [Help Net Security: OWASP prompt injection 2026](https://www.helpnetsecurity.com/2026/06/11/owasp-prompt-injection-ai-security-failures/)。

**本プロジェクトへの影響。三面。**
(i) **プロダクト教義の追認**: AI 悪用(プロンプト埋め込みマルウェア・エージェント駆動攻撃)の深化は、本ノードが最終権限を
**プロンプト操作不能な決定論アービタ**に置く教義を**さらに正当化**する(§3.1(i) と同趣旨、観測事実が追加)。→ 中核変更不要。
(ii) **ATT&CK v20 との接続**: DUSTMAKER の「設定ファイル/ローダコメントへのプロンプト埋め込み」は v20 の **T1698 Indirect
Prompt Injection** と **T1195.001(AI コーディングエージェント設定ファイル)**に対応——§3.1(ii-b) の追加助言マッピングの
実需を裏づける(観測事例が TTP に接地している)。
(iii) **【新規・開発工程の自衛】**: インフォスティーラが **AI 開発者設定を標的**にし、マルウェアが **worktree 内のファイルに
インジェクション文を仕込む**手口は、本プロジェクト自身の **Codex 委任(worktree の `AGENTS.md` / `spec.md` / `codex exec`)**に
対する脅威モデルでもある。`spec.md`・`AGENTS.md`・取り込む差分に**信頼できない注入文が混ざらない**ことを委任プロトコルの
衛生として明記する価値がある(→ §4 P3)。既存の **`--sandbox workspace-write` 固定 / network 要求即中断 / 許可リスト運用**
(§2B 規約)がこの面を既に緩和しているため、これは**注記レベル**で足りる。

---

## (4) 優先度付きアップデート提案

各項目: **提案 / 根拠+出典 / 想定工数 / リスク / 絶対制約との整合性**。すべてマスター判断待ち。
今月の主軸は **ATT&CK v20 出荷への対応(P2)**と**生モノ(Codex=GPT-6.1)更新(P1)**。いずれも中核契約を動かさない。

### P1(高・最小コスト・生モノ更新): 単一情報源の最新推奨世代を「Claude=Opus 5.5(据え置き)/ Codex=GPT-6.1(既定 Terra)」に確定

- **提案**: `development-guide.md` §0 の単一情報源方針どおり、本号(2026-11)をもって **Claude 側=Opus 5.5(9/22 以降据え置き)**、
  **Codex 側=GPT-6.1(既定 Terra、Sol/Luna/Astra から選択)** を確定値とする。他文書(CLAUDE.md / AGENTS.md / development-guide 本文)に
  世代名を**直書きしない**原則を再確認。設定変更なし(GPT-6.1 は Codex 既定として自動適用、Opus 5.5 は Claude Code 既定)。
- **根拠+出典**: [OpenAI Model release notes(GPT-6.1 Sol/Terra)](https://help.openai.com/en/articles/9624314-model-release-notes) /
  [Releasebot: OpenAI(GPT-6.1 Terra 2026-10-26, Codex CLI 0.164.0)](https://releasebot.io/updates/openai) /
  [Platform Docs: Opus 5.5 active latest](https://platform.claude.com/docs/en/models/opus-5-5/overview)。
- **想定工数**: 0.1 人日(本レポートの確定記述のみ。他文書は参照方式なので修正不要)。
- **リスク**: 低。de-hardcode 原則により Codex 片側更新でも多文書同時改訂を回避。
- **絶対制約整合性**: 抵触なし(モデル供給側の生モノ。スコアリング・依存・ランタイムに触れない)。

### P2(高・中コスト・watch 現実化): ATT&CK v20 対応 — (a) v19.2→v20 内容移行点検 +(b) AI 系5技術の追加助言マッピング評価

- **提案**: 10月 P3 の watch(ATT&CKcon 7.0 で v20 の前触れ)が現実化し、**v20 が 2026-10-13 に出荷**された。2段で起票する。
  - **(a) 内容移行点検**(繰越 + 新規の合算): 繰越の v19 Defense Evasion 分割(TA0005→Stealth / TA0112=Defense Impairment)に
    v19.2→v20 差分を合わせ、`attack/` マッピング・`correlate/` 相関ルール・advisory テンプレート・docs 内の戦術/技術参照を
    一覧化し移行手順を定める短報。**`attack_version` 固定でバイト同一リプレイは守られる**ため、これは**内容の正しさ**の点検。
  - **(b) 追加助言マッピング評価**: v20 の AI 系5技術(T1698/T1699/T1700/T1608.007/T1685.007)と T1195.001 更新を、
    **intel-tier の追加助言コンテキスト**として `attack/` に取り込む価値の評価(§3.1(ii-b)/§3.4(ii))。取り込む場合も
    **full-replace アダプタ経由・local.db 非破壊・7要素タプル外・助言専用・非属性文面**を厳守。実採用は別 PR(本号は評価起票まで)。
- **根拠+出典**: [MITRE: ATT&CK v20](https://attack.mitre.org/versions/v20/) /
  [MITRE ATT&CK blog: v20](https://medium.com/mitre-attack/attack-v20-9701dd75ffb4) /
  [Google GTIG: adversarial AI(DUSTMAKER)](https://cloud.google.com/blog/topics/threat-intelligence/from-prompting-to-autonomy-the-evolution-of-adversarial-ai)。
- **想定工数**: (a) 点検短報 1 人日 / (b) マッピング評価 0.5 人日。実際の v20 採用・マッピング実装は棚卸し結果次第で別 PR。
- **リスク**: 中。点検なしに世代を上げると、旧 TA0005 前提の advisory 出力が意味的にずれる。(b) で非属性文面を外すと ADR-0009 抵触。
  いずれも点検/評価止まりならリスクは低。
- **絶対制約整合性**: 抵触なし。②決定論(`attack_version` は既に7要素タプルの一員)・⑤local.db 不可侵(intel-tier full-replace、
  local-tier 非破壊)・①助言専用・非属性教義(ADR-0009)を維持する範囲での提案。

### P3(中・低コスト・新規): 委任プロトコルに「注入文混入防止」と Claude Code/Codex 新機能整合を注記

- **提案**: §3.4(iii) の脅威(AI 開発者設定/worktree ファイルへのプロンプト注入、DUSTMAKER 型)を受け、`development-guide.md`
  §2B/§2C に **(a)** 「`spec.md`・`AGENTS.md`・取り込む差分に信頼できない注入文が混ざらないことを確認する」衛生を一行追記、
  **(b)** Claude Code の**背景エージェントによるドラフト PR 起票**(本タスクの形)と **Claude in Chrome GA**(ブラウザ機能はクエリパス
  検証に使わない)を §2C に注記、**(c)** Codex CLI 0.164.0 の **enterprise MCP 認証**を §2C の MCP 衛生語彙に追加。
- **根拠+出典**: [Google GTIG(DUSTMAKER / AI 開発者設定)](https://cloud.google.com/blog/topics/threat-intelligence/from-prompting-to-autonomy-the-evolution-of-adversarial-ai) /
  [Help Net: OWASP prompt injection 2026](https://www.helpnetsecurity.com/2026/06/11/owasp-prompt-injection-ai-security-failures/) /
  [Claude Code changelog](https://code.claude.com/docs/en/changelog)。
- **想定工数**: 0.5 人日(文書注記 + 既存サンドボックス規約との整合確認)。
- **リスク**: 低。既存の `--sandbox workspace-write` 固定・network 即中断・許可リスト運用が既に緩和しているため注記レベルで足りる。
- **絶対制約整合性**: 抵触なし。④オフラインファースト・⑦依存最小性の精神を開発工程側へ延長。プロダクトへの MCP 導入はしない方針を再掲。

### P4(低・最小コスト・追認引用): ATT&CK v20 の prompt-injection 収載・TRACE-CTI・BOD 26-04 フォレンジック要求を論拠に反映

- **提案**: `docs/architecture.md` の失敗モデル節または `docs/scoring.md`/ADR-0009 の論拠節に、**(i)** ATT&CK v20 が
  Direct/Indirect Prompt Injection を正式 TTP 収載し、本ノードが最終権限をプロンプト操作不能な決定論アービタに置く教義を
  権威分類が裏付けること、**(ii)** TRACE-CTI が指摘する「予測と信頼の間の監査可能な境界」を本ノードの `reason[]`/リプレイ/
  監査チェーンが既に実現していること、**(iii)** CISA BOD 26-04 の KEV+完全制御層が3日以内フォレンジックを要求し、監査可能・
  再現可能なエビデンス生成の時宜性が増したこと、を**既存設計の外部追認**として1〜2文引用する。設計変更なし。
- **根拠+出典**: [MITRE ATT&CK v20(AI TTP)](https://medium.com/mitre-attack/attack-v20-9701dd75ffb4) /
  [arXiv: TRACE-CTI](https://arxiv.org/pdf/2607.24563) /
  [CISA: BOD 26-04 実装ガイダンス](https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk)。
- **想定工数**: 0.25 人日(文書のみ)。
- **リスク**: 低。
- **絶対制約整合性**: 抵触なし(論拠補強のみ。重み表・タプル・契約に触れない)。

### P5(中・低コスト・継続): README の基準線テスト数(583)を単一情報源参照へ(乖離さらに拡大)

- **提案**: `README.md`(現在「currently 583 tests」)は、単一情報源である CLAUDE.md / `development-guide.md` §0 の
  **現行基準線(1437)と乖離がさらに拡大**(10月号時点の §0=1213 から 1437 へ進み、README だけ 583 に取り残された)。README を
  **具体数の直書きから、単一情報源を参照する表現へ改める**提案を再掲する。※ 実際の現行本数は単一情報源
  (`python -m pytest tests/unit -q` 実測)を正とし、本レポートでは値を確定させない。
- **根拠+出典**: 内部保守衛生(8月 P1 以降の de-hardcode 方針の未完部分)。外部トレンドではなく陳腐化点検として計上。
- **想定工数**: 0.25 人日(文書のみ)。
- **リスク**: 低。乖離を放置すると新規読者が古い基準線(583)を信じる。乖離が大きいほど害も大きい。
- **絶対制約整合性**: 抵触なし(文書表現の整合。ランタイム・スコアリング・依存に触れない)。

---

## (5) 据え置き・非推奨と判断した項目とその理由

| 項目 | 判断 | 理由 |
|---|---|---|
| **中核教義(助言専用・決定論・オフライン・非属性・LLM は説明のみ)の変更** | 現行維持 | ATT&CK v20 が prompt injection を TTP 収載([MITRE v20](https://medium.com/mitre-attack/attack-v20-9701dd75ffb4))、TRACE-CTI が「予測と信頼の監査可能境界」を要件化([arXiv](https://arxiv.org/pdf/2607.24563))、GTIG の DUSTMAKER・BOD 26-04 の3日フォレンジック——**すべて教義を追認**。動かす動機なし。 |
| **ATT&CK v20 AI 系5技術の `threat_score` 直結** | **非推奨** | 助言マッピング(§4 P2b)は intel-tier の追加助言であって**スコア入力ではない**。スコア重みに直結させると F-2/F-8(byte-identical replay)と ADR-0006 を破壊。取り込むなら 7要素タプル外・full-replace・非属性文面に限る。 |
| **EPSS を主指標化 / `threat_score` へ混入** | **非推奨** | EPSS は ML 由来の日次確率値。7要素タプルに入れると byte-identical replay を破壊し ADR-0006 改訂が必要。ADR-0014 が副次限定・`epss_generation` を 7-tuple 外に置く形で foreclose 済み。EPSS v5 のまま値も安定。 |
| **ML/embedding/LLM ベースの behavioral scoring 採用** | **非推奨** | ADR-0009 が生成・類似度・スコアリングでの ML/embedding/clustering/LLM を明示禁止。市場の予測型 CTI は ML だが説明可能性が痛点——決定論選択が検証可能性で正当化される。**覆すなら shadow-only 節を超える新 ADR が必須**。 |
| **プロダクトへの MCP 導入 / 助言 API の MCP サーバ公開** | 据え置き | 仕様は 2026-07-28 で成熟(stateless core)だが、MCP Apps(server-rendered UI)で攻撃面が増える。offline-first・依存最小性・助言専用に照らし価値対リスク過大。将来議論なら ADR 案件。開発工程側 §2C の衛生更新は別物(P3c)。 |
| **Claude Code ネイティブ subagents(Agent Teams)で Codex を置換** | 据え置き(評価タスク化) | Agent Teams は Option B の機構的相似を強めたが、**別ベンダ併用の敵対的多様性**(写経レビュー回避)を失う。Opus 5.5・GPT-6.1 とも**フロンティア**で能力勾配は決め手にならず、拙速な置換を戒める。§2B 注記どおり ADR 相当の別タスクで評価。 |
| **Codex の使用モデル切替対応(GPT-6.1 Terra)** | 対応不要 | GPT-6.1(既定 Terra)は Codex 既定として自動適用。指示書は世代名を §0 単一情報源に委譲済みで、直書き修正は不要(P1 で確定)。 |
| **STIX 2.2 / TAXII 2.2 への追随** | 現行維持 | 2.2 は OASIS CTI TC の未解決 issue に留まり未公表、STIX/TAXII 2.1 が唯一の現行標準([OASIS CTI TC](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=cti))。ADR-0002/0005 は陳腐化せず。 |
| **BOD 26-04「2026-12-07 完全運用」記述(10月号)** | **補正** | 本号調査で当該固定期日を一次確認できず。BOD 26-04 は**固定期日を廃し脆弱性ごとの 3/14/60 日タイムライン表**へ移行([CISA 実装ガイダンス](https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk))。10月号の表現は「連邦のリスクベース移行が進行中」と理解するのが妥当。 |
| **NIST LEV の取込** | 据え置き(将来候補) | 9月号の判断(LEV は EPSS 時系列上の純粋演算で決定論親和だが、依然 NIST 提案・フィード非存在)を踏襲。採用時も「副次・as-of 固定」の枠内に限る。 |
| **SQLite → PostgreSQL 移行** | 据え置き | ADR-0003 の移行トリガ(実測書込負荷)が未達。Pi 4 budget 内は SQLite WAL 継続が妥当。 |

---

## 付記: 陳腐化点検の総括(2026-11)

- **教義は11月時点でも陳腐化しておらず、むしろ一段強く追認された。** ATT&CK v20 の prompt-injection TTP 収載・
  TRACE-CTI の監査可能境界の要件化・GTIG の自律エージェント資格情報窃取(DUSTMAKER)・BOD 26-04 の3日フォレンジック
  要求——いずれも「助言専用・決定論・監査可能・非属性・プロンプト操作不能な最終権限」を追認する。中核を動かす提案はない。
- **今月の主アクションは ATT&CK v20 対応(P2)**——10月 P3 の watch が現実化し、v19.2→v20 内容移行点検(繰越 + 新規)と
  AI 系5技術の intel-tier 追加助言マッピング評価の2段が着手可能になった。いずれも `attack_version` 固定で決定論を守る。
- **生モノ churn は今月 Codex 側のみ**(Claude=Opus 5.5 据え置き / Codex=GPT-6.1 既定 Terra)。P1 で単一情報源を確定。
- **プロダクト層の外部版は据え置き**(EPSS v5・STIX/TAXII 2.1)。README 基準線(583 vs 単一情報源 1437)の乖離は拡大(P5)。
- **MCP は本プロジェクトのランタイムに無関係**(Codex 側の enterprise MCP 認証拡張は開発工程 §2C の語彙更新候補)。
- **10月号の BOD 26-04「2026-12-07 完全運用」記述を §5 で補正**(脆弱性ごとのタイムライン表へ移行)。

### 参照一覧(主要出典)

- Claude モデル(Opus 5.5 据え置き): <https://www.anthropic.com/claude-opus-5-5> / <https://platform.claude.com/docs/en/models/opus-5-5/overview> / <https://9to5mac.com/2026/09/22/anthropic-upgrades-claude-with-new-opus-5-5-model-details-here/>
- OpenAI Codex / GPT-6.1(Sol 9/29・Terra 10/26, Codex CLI 0.164.0): <https://help.openai.com/en/articles/9624314-model-release-notes> / <https://releasebot.io/updates/openai>
- Claude Code 新機能(背景エージェントのドラフト PR / Chrome GA / モデルフォールバック要約): <https://code.claude.com/docs/en/changelog> / <https://www.gradually.ai/en/changelogs/claude-code/>
- MITRE ATT&CK v20(2026-10-13, AI TTP 収載): <https://attack.mitre.org/versions/v20/> / <https://medium.com/mitre-attack/attack-v20-9701dd75ffb4> / <https://www.securityweek.com/mitre-attck-v20-catalogs-ai-abuse-mfa-bypass-water-utility-attacks/> / <https://cybersecuritynews.com/mitre-attck-v20-released/>
- TRACE-CTI(監査可能境界): <https://arxiv.org/pdf/2607.24563>
- AI 悪用(GTIG DUSTMAKER / 自律エージェント資格情報窃取 / OWASP prompt injection): <https://cloud.google.com/blog/topics/threat-intelligence/from-prompting-to-autonomy-the-evolution-of-adversarial-ai> / <https://thehackernews.com/2026/09/autonomous-ai-agents-compromise.html> / <https://www.helpnetsecurity.com/2026/06/11/owasp-prompt-injection-ai-security-failures/>
- EPSS v5: <https://craci.com/epss> / <https://www.parameter.ai/learn/exploit-prediction-scoring-system>
- CISA BOD 26-04(リスクベース期日): <https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk> / <https://www.tenable.com/blog/cisa-bod-26-04-FAQ-vulnerability-remediation-impact>
- OASIS STIX/TAXII 2.1(2.2 は未公表): <https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=cti> / <https://github.com/oasis-tcs/cti-stix2/issues>
</content>
</invoke>
