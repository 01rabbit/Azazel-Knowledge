# 技術偵察レポート — AI・関連技術情勢と Azazel-Knowledge 陳腐化点検(2026-09)

作成日: 2026-09-01 / 担当: Claude Code(技術偵察) / 対象 main: `9f10e06`(Phase 1 + Phase 2 Behavioral CTI + AZ-06 deception effectiveness / Outcome Memory v0 / ADR-0010〜0014 まで反映)

> **位置づけ。** 本レポートは**提案のみ**であり、コード・設計・ADR を一切変更しない。
> 各提案は CLAUDE.md 絶対制約1〜8(助言専用・決定論スコアリング・決定論入力規律・
> オフラインファースト・local.db 不可侵・フェイルクローズド・依存最小性・助言ルールのみ)と
> ADR-0001〜0014 を**尊重する**。教義に反する案は「非推奨」と明記し、覆すなら新 ADR が
> 要る旨を添えた(§5)。採否の最終判断はマスターに委ねる。
>
> **前月からの継続。** 本書は [`ai-landscape-2026-08.md`](ai-landscape-2026-08.md) の後継。
> 8月レポートの結論(中核教義は陳腐化せず、陳腐化は「生モノ」= モデル名・基準線・依存版・
> 外部データ版に集中)は9月も維持される。**8月の提案は大半が着手済み**——P1(開発指示書の
> モデル de-hardcode)は `development-guide.md` §0 の単一情報源化として、P4(開発 MCP 衛生)は
> 同 §2C として実装され、**P2(EPSS 副次シグナル化)は [ADR-0014](../adr/0014-epss-advisory-ingest.md)
> 設計スパイクとして起票済み**。本書は「8月以降に新たに動いた外部事実」と「その事実が既に着手済みの
> 設計へ与える差分」に焦点を絞る。特に **EPSS v5・ATT&CK v19 という2つの版更新**が、
> 決定論リプレイ規律(F-2/F-8)に対して**具体的な版固定アクション**を要求する点が今月の核心。

---

## (1) 要約(3行)

1. **中核教義は9月時点でも陳腐化していない——外部からの追認はさらに強まった。** Pentera の
   「決定論オーケストレーションに AI を内包・リプレイ可能性が検証の要」論(2026-04)は健在で、
   CISA **BOD 26-04**(2026-06-10)が KEV 主・多シグナルの脆弱性優先度を連邦標準として明文化。
   市場は agentic SOC へ疾走するが、その未解決課題は**説明可能性と検証可能性**——本ノードが埋める隙間そのもの。
2. **開発基盤層は8月から世代が進んでいない(生モノの churn が鈍化)。** フロンティアは **Claude Opus 5**
   のまま(5.1 は未登場)、Codex の既定モデルが **GPT-5.6 "Sol"**(2026-07-09 GA、>20% 値下げ)に更新。
   SWE-Bench Pro で Codex ≈64.6% / Claude 系 ≈80% と実測差があり、**Claude=指揮/敵対レビュー・Codex=実装**の
   分業は追認された。Claude Code に `--restricted` 等の隔離強化が入り、本リポの worktree 分離教義と噛み合う。
3. **プロダクト層で「決定論を壊さずに版を固定せよ」という新宿題が2件出た。** **EPSS v5**(2026-06-15、v4 比
   約23%高精度・値が実質変化)と **ATT&CK v19**(2026-04-28、Defense Evasion を Stealth と Defense
   Impairment に分割)。いずれも本ノードの7要素タプル(`intel_generation`/`attack_version`)で版固定する
   設計だが、**EPSS はモデル版まで固定しないと世代スワップで byte-identical replay が壊れる**——
   着手済みの ADR-0014 スパイクへ**明示追記**すべき(§4 P1)。中核を動かす提案は今月も不要。

---

## (2) 開発基盤層の新動向と本プロジェクトへの影響

### 2.1 フロンティアモデル: 世代は据え置き、価格と実装側モデルが動いた

| ベンダ | 8月時点 | 9月時点(本書) | 出典 |
|---|---|---|---|
| Anthropic | Opus 5(2026-07-24 GA)/ Sonnet 5 | **変化なし**(Opus 5.1 / Haiku 5 は未登場)。Sonnet 5 の導入価格は 2026-08-31 で終了、**2026-09-01 から標準 $3/$15** | [Anthropic Opus 5](https://www.anthropic.com/news/claude-opus-5) / [Models overview](https://platform.claude.com/docs/en/about-claude/models/overview) / [Sonnet 5 価格](https://qcode.cc/en/claude-sonnet-5) |
| OpenAI | Codex 推奨 = GPT-5.5 | **Codex 既定 = GPT-5.6 "Sol"**(2026-07-09 GA、Sol/Terra/Luna 系)。2026-08-21 に API >20% 値下げ | [OpenAI GPT-5.6](https://openai.com/index/gpt-5-6/) / [Codex 統計](https://www.gradually.ai/en/codex-statistics/) |
| コーディング実測 | Terminal-Bench 中心 | **SWE-Bench Pro: GPT-5.6 Sol ≈64.6% / Claude 系 ≈80%**(GA モデル間) | [morphllm SWE-Bench Pro](https://www.morphllm.com/swe-bench-pro) / [lmcouncil](https://lmcouncil.ai/benchmarks) |

**本プロジェクトへの影響。** (a) **世代 churn が鈍化**した。8月レポートが P1 で懸念した「モデル名の生モノ陳腐化」は、
`development-guide.md` §0 が**最新推奨世代を `docs/reports/ai-landscape-*.md` 最新号に単一情報源化**したことで
既に構造的に解決済み。よって本書は最新世代を確定させるだけでよい:**Claude 側=Opus 5、Codex 側=GPT-5.6 "Sol"**。
(b) SWE-Bench Pro の実測差(Codex 64.6% < Claude 系 80%)は、**指揮官・敵対レビュー役に Claude 系を、実装労働に
Codex を置く**現行分業(§2/§2B)が能力面でも合理的であることを裏づける。GPT-5.6 は Codex 既定なので**設定変更は不要**、
値下げは実装コストを下げるのみで教義に無影響。

### 2.2 Claude Code: 隔離・サンドボックス強化が worktree 教義と噛み合う

- **`--restricted` モード**(v2.1.248, 2026-08-28): コマンド実行を外し、作業ディレクトリ外のファイルアクセスを遮断。
- **サンドボックス堅牢化**(2026-08): file ツールの symlink traversal 修正、plugin path 検証、Windows NT 名前空間
  path 拒否、MCP `headersHelper` の信頼ダイアログ必須化、権限プレビューでの資格情報マスク。
- **`PreModelSwitch`/`PostModelSwitch` フック**とセッションフック拡張、バックグラウンド/クラウドセッション管理 CLI
  (`attach`/`logs`/`stop`/`respawn`/`rm`)。バイナリは zstd 圧縮で ~340MB→~75MB。
- **Code with Claude 2026** はエージェント/インフラ機能のみで**新フロンティアモデルの投入はなし**。
- 出典: [releasebot: Claude Code](https://releasebot.io/updates/anthropic/claude-code)(2026-08-28)/ [MindStudio: Code with Claude 2026](https://www.mindstudio.ai/blog/code-with-claude-2026-new-agent-features)。

**本プロジェクトへの影響。** `--restricted` と Aug のサンドボックス修正群は、本リポの
**「1タスク=1 worktree=1ブランチ、本体ツリーは触らせない」**(§2B)・**「開発ツールチェーン供給網衛生」**(§2C)と
**同じ方向**。指揮官セッション側で `--restricted` を評価する価値がある(§4 P4)。`headersHelper` 信頼ダイアログ必須化は、
§2C の「外部 MCP は許可リスト・変更管理イベント扱い」を Claude Code 側の機構が追認した形。

### 2.3 MCP: 仕様は 2026-07-28 のまま、供給網リスクは population レベルで依然高い

- **仕様は 2026-07-28 が最新**。2026-08-22 のロードマップは、次段(agentic messaging・HTTP-native transport 統一・
  agent identity[DPoP/WIF/token exchange]・progressive tool discovery)を予告するが**日付コミットなし**。
- **認可の方向転換**: クライアント登録は **CIMD(Client ID Metadata Documents)推奨**へ、
  **Dynamic Client Registration(DCR)は正式に deprecated**(後方互換は残る)。
- **供給網の実態は依然劣悪**: Wiz は「クラウド環境の約6件に1件が MCP サーバを露出、大半が pre-auth の
  2024-11-05 プロトコルで交渉、一部は metadata endpoint への SSRF 可能」と報告。Amazon Q Developer VS Code 拡張は
  悪意あるリポを開くだけで MCP 自動実行経由の任意コード実行+クラウド資格情報窃取(language server 1.65.0 で修正)。
- 出典: [MCP ロードマップ](https://blog.modelcontextprotocol.io/posts/mcp-roadmap/)(2026-08-22)/ [MCP 2026-07-28](https://blog.modelcontextprotocol.io/posts/2026-07-28/) / [Wiz: exposed MCP servers](https://www.wiz.io/blog/the-risk-hiding-behind-exposed-mcp-servers) / [Wiz: Amazon Q](https://www.wiz.io/blog/amazon-q-vulnerability) / [NSA CSI: MCP Security](https://media.defense.gov/2026/Jun/02/2003943289/-1/-1/0/CSI_MCP_SECURITY.PDF)(2026-06-02)。

**本プロジェクトへの影響。** 8月と結論不変——**本ノードのランタイムは MCP を使わない**(コア依存は
stdlib + PyYAML + idna + PyNaCl、Fabric も `api` extra 限定)。population レベルの MCP 脆弱性・Amazon Q 事案は、
**MCP をプロダクト攻撃面に入れない判断の正しさを追認**するだけ。開発工程側で MCP を繋ぐ場合の §2C を、
新事実で**微更新できる**:**DCR 廃止→CIMD 前提、`headersHelper` 信頼ダイアログ必須**を語彙に追加(§4 P4)。

---

## (3) プロダクト設計層の新動向と本プロジェクトへの影響

### 3.1 【要対応】EPSS v5 が登場(値が実質変化)——決定論リプレイのモデル版固定が必須に

- **EPSS v5 が 2026-06-15 に公開**(データセットタグ `v2026.06.15`、Empirical Security が 2026-05-13 発表)。
  v4(2025-03-17)比で**約23%高精度**を主張(同一 2026-05-04 テストで v5=0.633 vs v4=0.514)。EPSS は依然
  FIRST EPSS SIG の **ML モデル**で、CVE ごとに「今後30日の悪用確率 [0,1]」を出力。
- 出典: [Empirical Security: EPSS v5](https://natlawreview.com/press-releases/empirical-security-releases-epss-v5)(2026-05-13)/ [Wikipedia: EPSS](https://en.wikipedia.org/wiki/Exploit_Prediction_Scoring_System) / [FIRST EPSS](https://www.first.org/epss/)。

**本プロジェクトへの影響(核心)。** [ADR-0014](../adr/0014-epss-advisory-ingest.md) は EPSS を**副次コンテキスト限定**とし、
`threat_score` への混入(7要素タプル汚染 → F-2/F-8 破壊)を明示的に禁じた——**方向は正しい**。だが ADR-0014 は
「v4 が現行」を暗黙前提にした時期の起票であり、**新事実は「EPSS のモデル版そのものが v4→v5 で値を実質的に変える」**点。
本ノードの as-of 世代固定は「同一入力→バイト同一」を保証するが、**モデル版が世代スナップショットに記録されていなければ、
v4→v5 スワップは「同じ CVE の EPSS 値が静かに変わる」ことになり、世代跨ぎのリプレイ整合が崩れる**。
→ **ADR-0014 スパイクの決定論境界に「EPSS モデル版(`v4`/`v5`)を `intel_generation` スナップショットへ版固定する」を
明示追記**すべき(§4 P1)。実装前の設計段階での追記なので低コスト。

### 3.2 【要対応】MITRE ATT&CK v19 が Defense Evasion を分割——`attack_version` 固定は効くが内容移行の点検が要る

- **ATT&CK v19 が 2026-04-28 公開**。構造上の大変更は **Defense Evasion(TA0005)の分割**:
  **Stealth(TA0005)** と **Defense Impairment(TA0112)** の2戦術へ。ICS へのサブテクニック追加、Mobile の
  Detection Strategies 開始、AI 活用/ソーシャルエンジニアリング系テクニック追加も。件数: software 949 / groups 178 / campaigns 59。
- 出典: [ATT&CK updates April 2026](https://attack.mitre.org/resources/updates/updates-april-2026/)(2026-04-28)/ [Security Boulevard: v19 Defense Evasion split](https://securityboulevard.com/2026/04/mitre-attck-v19-drops-april-28-how-to-prepare-your-soc-for-the-defense-evasion-split/)。

**本プロジェクトへの影響。** 本ノードは7要素タプルに **`attack_version`** を含めるため、**リプレイ整合そのものは保護される**
(ATT&CK 世代を上げなければ現行出力は不変、上げれば別世代=別リプレイ空間)——この設計は正しく機能する。ただし
**TA0005 の意味が「Defense Evasion」→「Stealth」に変わり、impairment 系テクニックは TA0112 へ移動**したため、
ATT&CK フィード世代を v19 に上げる前に、**旧 TA0005 セマンティクスに依存する内容**(TTP マッピング・相関ルール・
advisory テンプレート・docs 内の戦術名参照)を棚卸しする必要がある。→ 移行点検を起票(§4 P2)。

### 3.3 KEV 主・多シグナル優先度が連邦標準化(教義の追認)+ EPSS/KEV/SSVC/LEV の実務合成

- **CISA BOD 26-04**(2026-06-10)が純 CVSS 依存を廃し、**公開露出・KEV 収載・悪用の自動化可能性・システム全体制御**の
  4シグナル+3/7/14/30日 SLA へ移行。**KEV 主の多シグナル優先度**を連邦レベルで明文化。
- 2026 実務合成は「加重平均ではなく階層パイプライン」:**KEV(確定ゲート)→ EPSS(残りの確率トリアージ)→
  SSVC/資産文脈(判断)→ LEV(遡及確率の後詰め)**。CVSS は **v4.0 が現行**(v4.1/v5 なし)、SSVC 現行、
  NIST **LEV(CSWP 41, 2025-05-19)は依然「提案」**でフィード化されていない。
- 出典: [CISA BOD 26-04 解説](https://www.cybrsecmedia.com/from-cvss-to-kev-cisa-rewrites-federal-patching-priorities/)(2026-06-10)/ [Aptori: LEV/EPSS/KEV](https://www.aptori.com/blog/comparing-nist-lev-epss-and-kev-for-vulnerability-prioritization) / [Picus: CVSS/EPSS/KEV/SSVC/LEV/PXS](https://www.picussecurity.com/resource/blog/comparing-cvss-epss-kev-ssvc-lev-and-pxs-from-scores-to-security-proof) / [FIRST CVSS v4.0](https://www.first.org/cvss/v4.0/) / [NIST CSWP 41 (LEV)](https://csrc.nist.gov/pubs/cswp/41/likely-exploited-vulnerabilities-a-proposed-metric/final)。

**本プロジェクトへの影響。** 本ノードの既存設計——**`cve_exploited`(KEV 由来, 重み 0.15, `applies_when:[eve_alert]`)を
確定事実として主に据え、EPSS は副次コンテキスト止まり**(ADR-0014)——は、**BOD 26-04 の「KEV 主・多シグナル」を
そのまま先取り**している。KEV/SSVC は決定論的ルックアップ/決定木で、ML は EPSS の**内部にのみ**閉じており、本ノードは
それを**外部で計算済みのスナップショット入力**として取り込む(スコアリングパスで ML を走らせない)——階層合成は
決定論方針と両立する。LEV は EPSS 時系列上の純粋な数学演算で**決定論親和的**だが、まだ NIST 提案・フィード非存在のため
今は据え置き(§5)。→ 中核変更は不要。この整合は scoring.md/ADR 論拠で**外部追認として引用できる**(§4 P5)。

### 3.4 「静的 IOC → 行動 CTI」潮流と agentic SOC の疾走——教義の逆張りが niche になる

- 潮流は「静的 IOC(IP/ハッシュ)→ TTP/行動ベース」へ継続移行(TTP は堅牢でローテーションされにくい)。
  ただし主流ベンダ実装は **ML ベースの適応的行動ベースライン**が中心で、**説明可能性が未解決の痛点**として名指しされる
  (「なぜその結論に達したかアナリストが理解できない」)。市場は **agentic AI in the SOC**(自律的に調査計画・実行)へ
  疾走(87% が2026優先課題、agentic AI security 市場 ~$1.65B[2026]→~$13.5B[2032], CAGR ~42%)。新たな脅威クラスとして
  **AI-to-AI 攻撃**(悪性エージェントが他 AI を API/プロンプト経由で自律攻撃)も浮上し、防御要件は「知的・**説明可能**・耐性」。
- **Pentera 8**(2026 Q2 GA)は「決定論ロジックが攻撃チェーン実行を定義(安定・反復可能・監査可能)、AI はガードレール内で
  ペイロード適応/シグナル解釈のみ」の二層アーキを出荷し、「手法が実行ごとに変わると改善を検証不能」と明言。
- 出典: [SL Cyber: CTI 2026](https://www.slcyber.io/blog/what-is-cti-the-essential-guide-to-cyber-threat-intelligence-in-2026) / [THN: Deterministic + Agentic](https://thehackernews.com/2026/04/deterministic-agentic-ai-architecture.html)(2026-04-15) / [Pentera Platform](https://pentera.io/pentera-platform/) / [MarketsandMarkets: agentic AI security](https://www.marketsandmarkets.com/Market-Reports/agentic-ai-security-market-97017233.html) / [Cyware: 2026 proactive AI](https://www.cyware.com/blog/2026-the-year-when-cyber-threat-intelligence-evolves-into-proactive-ai)。

**本プロジェクトへの影響。二面性は8月と同じだが、9月はより鮮明。**
(i) 「行動を軸に脅威を特徴づける」**方向**は Phase 2 Behavioral CTI と合致し陳腐化していない。むしろ産業の
主流化が追い風。(ii) だが商用の**手段**(ML/embedding/clustering)は本ノードが**意図的に採らない**(ADR-0009)。
市場が説明可能性・検証可能性を未解決課題として自認し、Pentera が「決定論=検証可能性の前提、AI はガードレール内包」を
掲げ、AI-to-AI 攻撃面が「最終権限を prompt 操作不能な決定論アービタに置く」論拠を強める——**これらはすべて本ノードの
「決定論・説明可能・助言専用・オフライン」設計を追認**する。唯一の緊張は「no ML/no cloud/no agent が時代遅れに見える」
という**外形的誤読**だが、反論は「決定論+説明可能性+オフライン耐性こそ agentic 波が今まさに供給できていない性質」。
→ 中核を動かす提案は不要。§5 で「現行維持」。

### 3.5 標準・コーパス: STIX/TAXII 2.1 現行、Engage v1.0、SigmaHQ/YARA は継続更新

- **STIX 2.1 / TAXII 2.1 が依然 OASIS 唯一の現行標準**。**STIX 2.2 / TAXII 2.2 は未公表**(committee spec・working
  draft・日付付き 2.2 活動が CTI TC に見当たらず)。→ ADR-0002/0005 は陳腐化せず、追随不要。
- **MITRE Engage は v1.0 のまま**(2024-10 正式版、ATT&CK にマップ、2026 の大版更新なし)——[ADR-0012](../adr/0012-mitre-engage-ingest.md)
  スパイクの前提は有効。**SigmaHQ**(3,000+ ルール、2026 も継続追加)/ **YARA** コミュニティルールも継続——
  [ADR-0013](../adr/0013-yara-sigma-corpus-ingest.md) スパイクの前提も有効。
- 出典: [OASIS CTI TC](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=cti) / [STIX/TAXII 2.1 公表](https://www.oasis-open.org/2021/06/23/stix-v2-1-and-taxii-v2-1-oasis-standards-are-published/) / [MITRE Engage](https://engage.mitre.org/) / [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma/blob/master/README.md)。

**本プロジェクトへの影響。** 標準・コーパス層は**据え置き前提が有効**で、既起票スパイク(ADR-0012/0013)の土台に
変化なし。追随不要。

---

## (4) 優先度付きアップデート提案

各項目: **提案 / 根拠+出典 / 想定工数 / リスク / 絶対制約との整合性**。すべてマスター判断待ち。
今月は**新規外部事実に直結する2件(P1/P2)が最優先**で、いずれも既着手の設計・既決タプル規律への
**整合性追記/点検**であり、中核契約を動かさない。

### P1(高・低コスト・新規): ADR-0014 スパイクに「EPSS モデル版の世代固定」を明示追記

- **提案**: [ADR-0014](../adr/0014-epss-advisory-ingest.md)(EPSS 副次取込・実装前スパイク)の決定論境界に、
  **「EPSS モデル版(`v4`/`v5`…)を `intel_generation` の世代スナップショットに版固定し、モデル版のスワップは
  必ず新世代として扱う(同一 CVE の EPSS 値が世代内で静かに変わらないことを保証)」**を1節として追記する。
  EPSS 値・percentile だけでなく**モデル版を as-of の一部にする**のが要点。**実装は行わない**(ADR 追記のみ)。
- **根拠+出典**: EPSS v5 が 2026-06-15 に公開され v4 比で値が実質変化([Empirical Security](https://natlawreview.com/press-releases/empirical-security-releases-epss-v5) / [Wikipedia EPSS](https://en.wikipedia.org/wiki/Exploit_Prediction_Scoring_System))。
  ADR-0014 は「EPSS を副次限定・`threat_score` に混ぜない」までは定めたが、**モデル版の世代固定**には触れていない。
- **想定工数**: 0.25〜0.5 人日(ADR 1節の追記のみ、コード変更なし)。
- **リスク**: 低。**未追記のまま将来 v4→v5 を取り込むと、世代跨ぎリプレイ整合が静かに崩れうる**——追記の遅れ自体が唯一の害。
- **絶対制約整合性**: **②決定論スコアリング・③決定論入力規律を強化する**方向。EPSS は依然副次コンテキスト止まり
  (`threat_score` 非混入 = F-2/F-8 不変)であり、①助言専用・④オフラインファースト(取得は worker/bundle)にも抵触なし。
  **重み表を触る案ではない**ので ADR-0006 改訂は不要。

### P2(高・中コスト・新規): ATT&CK v19 の Defense Evasion 分割に対する内容移行点検

- **提案**: ATT&CK フィード世代を v19 に上げる前提で、**旧 TA0005(Defense Evasion)セマンティクスに依存する内容を
  棚卸しする点検短報**を起票する。対象: `attack/` のマッピング、`correlate/` の相関ルール、advisory テンプレート、
  docs 内の戦術名参照。TA0005 が「Stealth」へ改称され、impairment 系が **TA0112(Defense Impairment)** へ移動した点を
  一覧化し、世代更新時の移行手順を定める。**リプレイ整合は `attack_version` 固定で既に保護される**ため、これは
  「世代を上げるときに何を書き換えるか」の**内容移行**の点検であって、決定論規律の変更ではない。
- **根拠+出典**: [ATT&CK v19(2026-04-28)](https://attack.mitre.org/resources/updates/updates-april-2026/) の戦術分割
  ([Security Boulevard](https://securityboulevard.com/2026/04/mitre-attck-v19-drops-april-28-how-to-prepare-your-soc-for-the-defense-evasion-split/))。
- **想定工数**: 点検短報 1 人日。実際の v19 移行(採用時)は棚卸し結果次第で別 PR。
- **リスク**: 中。**点検なしに世代を上げると、旧 TA0005 前提の advisory 出力が意味的にずれる**。`attack_version` 固定が
  バイト同一リプレイは守るが、**内容の正しさ**は自動では守られない。点検止まりならリスクは低。
- **絶対制約整合性**: 抵触なし。②決定論(`attack_version` は既に7要素タプルの一員)・⑤local.db 不可侵(intel-tier の
  full-replace アダプタ経由、local-tier 非破壊)を維持。

### P3(中・低コスト・生モノ): README とドキュメントの基準線テスト数の整合(単一情報源への統一)

- **提案**: `README.md`(現在「currently 583 tests」)と `development-guide.md` §0(単一情報源「現在 = 591」)の
  **テスト基準線の数値が乖離**している。README を**具体数の直書きから、単一情報源(§0)を参照する表現へ改める**提案を
  起票する。8月 P1 で確立した「生モノ(モデル名・基準線)は1箇所に集約」原則を README にも延長する。
  ※ 実際の現行本数は §0 の単一情報源(`python -m pytest tests/unit -q` 実測)を正とし、本レポートでは値を確定させない。
- **根拠+出典**: 内部保守衛生(8月 P1 の de-hardcode 方針の未完部分)。外部トレンドではなく陳腐化点検として計上。
- **想定工数**: 0.25 人日(文書のみ)。
- **リスク**: 低。乖離を放置すると新規読者が古い基準線を信じる。
- **絶対制約整合性**: 抵触なし(文書表現の整合。ランタイム・スコアリング・依存に触れない)。

### P4(中・低コスト・8月 P4 の微更新): 開発工程の隔離・供給網衛生を新事実で更新

- **提案**: (a) 指揮官セッションでの **Claude Code `--restricted` モード**採用を評価し、採用可否と適用範囲を
  `development-guide.md` §2B/§2C に注記(worktree 分離教義と機構的に整合)。(b) §2C の MCP 衛生記述を新事実で微更新:
  **「DCR は deprecated、クライアント登録は CIMD 前提」「`headersHelper` は信頼ダイアログ必須」**を語彙に追加。
  **プロダクトへの MCP 導入は現時点で行わない**方針は不変で再掲。
- **根拠+出典**: Claude Code Aug 隔離強化([releasebot](https://releasebot.io/updates/anthropic/claude-code))、
  MCP 認可転換(DCR→CIMD)([MCP 2026-07-28](https://blog.modelcontextprotocol.io/posts/2026-07-28/))、
  供給網事案([Wiz: Amazon Q](https://www.wiz.io/blog/amazon-q-vulnerability) / [NSA CSI](https://media.defense.gov/2026/Jun/02/2003943289/-1/-1/0/CSI_MCP_SECURITY.PDF))。
- **想定工数**: 0.5 人日(評価+文書更新。`--restricted` 実採用は別途)。
- **リスク**: 低。未更新のまま外部 MCP を繋ぐ/隔離強化を見送るほうがリスク。
- **絶対制約整合性**: 抵触なし。④オフラインファースト・⑦依存最小性の精神を開発工程側へ延長。

### P5(低・最小コスト・追認引用): KEV 主・多シグナル優先度の外部追認を論拠に反映

- **提案**: `docs/scoring.md` または ADR-0014 の論拠節に、**CISA BOD 26-04(KEV 主・多シグナル優先度の連邦標準化)**と
  **KEV→EPSS→SSVC→LEV の階層合成が2026実務標準**である旨を、**既存設計(KEV 主・EPSS 副次)の外部追認**として1〜2文引用する。
  設計変更は伴わない(引用のみ)。
- **根拠+出典**: [CISA BOD 26-04](https://www.cybrsecmedia.com/from-cvss-to-kev-cisa-rewrites-federal-patching-priorities/)(2026-06-10)/ [Aptori LEV/EPSS/KEV](https://www.aptori.com/blog/comparing-nist-lev-epss-and-kev-for-vulnerability-prioritization) / [Picus 比較](https://www.picussecurity.com/resource/blog/comparing-cvss-epss-kev-ssvc-lev-and-pxs-from-scores-to-security-proof)。
- **想定工数**: 0.25 人日(文書のみ)。
- **リスク**: 低。
- **絶対制約整合性**: 抵触なし(論拠補強のみ。重み表・タプルに触れない)。

---

## (5) 据え置き・非推奨と判断した項目とその理由

| 項目 | 判断 | 理由 |
|---|---|---|
| **中核教義(助言専用・決定論・オフライン・非属性・LLM は説明のみ)の変更** | 現行維持 | Pentera「決定論=検証可能性の前提、AI はガードレール内包」([THN](https://thehackernews.com/2026/04/deterministic-agentic-ai-architecture.html))、CISA BOD 26-04 の KEV 主標準化、agentic 波の説明可能性/検証可能性の未解決、AI-to-AI 攻撃面——**すべて教義を追認**。動かす動機なし。 |
| **EPSS を主指標化 / `threat_score` へ混入** | **非推奨** | EPSS は ML 由来の日次確率値。7要素タプルに入れると F-2/F-8(byte-identical replay)を破壊、ADR-0006 改訂が必要。ADR-0014 が既に副次限定で foreclose 済み。v5 登場で値が動くぶん混入の害は増した。 |
| **ML/embedding/LLM ベースの behavioral scoring 採用** | **非推奨** | ADR-0009 が生成・類似度・スコアリングでの ML/embedding/clustering/LLM を明示禁止。市場は ML ベースだが説明可能性が未解決の痛点([SL Cyber](https://www.slcyber.io/blog/what-is-cti-the-essential-guide-to-cyber-threat-intelligence-in-2026))——決定論選択が検証可能性で正当化される。**覆すなら shadow-only 節を超える新 ADR が必須**。 |
| **NIST LEV の取込** | 据え置き(将来候補) | LEV は EPSS 時系列上の純粋演算で**決定論親和的**だが、依然 NIST 提案(CSWP 41)でフィード非存在([NIST](https://csrc.nist.gov/pubs/cswp/41/likely-exploited-vulnerabilities-a-proposed-metric/final))。標準化・フィード化まで待つ。採用時も EPSS 同様「副次・as-of 固定」の枠内に限る。 |
| **STIX 2.2 / TAXII 2.2 への追随** | 現行維持 | 2.2 は未公表、STIX/TAXII 2.1 が OASIS 唯一の現行標準([OASIS CTI TC](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=cti))。ADR-0002/0005 は陳腐化せず。 |
| **プロダクトへの MCP 導入 / 助言 API の MCP サーバ公開** | 据え置き | 仕様は 2026-07-28 で成熟だが供給網リスクは population レベルで継続(Wiz「6環境に1つ露出」、Amazon Q 事案)。offline-first・依存最小性・助言専用に照らし価値対リスク過大。将来議論なら ADR 案件。 |
| **Claude Code ネイティブ subagents で Codex を置換** | 据え置き(評価タスク化) | Dynamic Workflows/Performance Outcomes は敵対的レビュー・ループの相似形だが、**別ベンダ併用の敵対的多様性**を失う。SWE-Bench Pro 実測(Codex 64.6% < Claude 系 80%)は「実装=Codex・敵対レビュー=Claude」分業の合理性を裏づけ、拙速な置換をむしろ戒める。§2B 注記どおり ADR 相当の別タスクで評価。 |
| **Codex の使用モデル切替対応** | 対応不要 | GPT-5.6 "Sol" は Codex 既定として自動適用済み。指示書は世代名を §0 単一情報源に委譲済みで、直書き修正は不要。 |
| **SQLite → PostgreSQL 移行** | 据え置き | ADR-0003 の移行トリガ(実測書込負荷)が未達。Pi 4 budget 内は SQLite WAL 継続が妥当。 |

---

## 付記: 陳腐化点検の総括(2026-09)

- **教義は9月時点でも陳腐化しておらず、Pentera / CISA BOD 26-04 / agentic 波の説明可能性ギャップに追認されている。** 中核を動かす提案はない。
- **今月の新規宿題は「決定論を壊さずに外部データ版を固定せよ」の2件**——**EPSS v5**(P1: ADR-0014 へモデル版固定を追記)と
  **ATT&CK v19 の戦術分割**(P2: 内容移行点検)。いずれも既決タプル規律(`intel_generation`/`attack_version`)の
  **整合を保つ追記/点検**であり、契約変更ではない。
- **8月提案は大半が着手済み**(P1 de-hardcode → §0、P4 MCP 衛生 → §2C、P2 EPSS → ADR-0014)。本書はその**上に載る差分**を扱う。
- **開発基盤層の生モノ churn は鈍化**(Opus 5 据え置き、Codex 既定=GPT-5.6)。残る生モノ乖離は README の基準線数値(P3)。
- **MCP は本プロジェクトのランタイムに無関係**(供給網事案は非導入判断を追認、開発工程側 §2C を微更新 = P4)。

### 参照一覧(主要出典)

- Claude モデル(Opus 5 / Sonnet 5 価格): <https://www.anthropic.com/news/claude-opus-5> / <https://qcode.cc/en/claude-sonnet-5>
- OpenAI Codex / GPT-5.6 "Sol": <https://openai.com/index/gpt-5-6/> / <https://www.gradually.ai/en/codex-statistics/>
- コーディング実測(SWE-Bench Pro): <https://www.morphllm.com/swe-bench-pro> / <https://lmcouncil.ai/benchmarks>
- Claude Code 新機能(--restricted / サンドボックス強化): <https://releasebot.io/updates/anthropic/claude-code>
- MCP(ロードマップ / DCR→CIMD / 供給網): <https://blog.modelcontextprotocol.io/posts/mcp-roadmap/> / <https://blog.modelcontextprotocol.io/posts/2026-07-28/> / <https://www.wiz.io/blog/the-risk-hiding-behind-exposed-mcp-servers> / <https://www.wiz.io/blog/amazon-q-vulnerability> / <https://media.defense.gov/2026/Jun/02/2003943289/-1/-1/0/CSI_MCP_SECURITY.PDF>
- EPSS v5: <https://natlawreview.com/press-releases/empirical-security-releases-epss-v5> / <https://en.wikipedia.org/wiki/Exploit_Prediction_Scoring_System> / <https://www.first.org/epss/>
- MITRE ATT&CK v19(戦術分割): <https://attack.mitre.org/resources/updates/updates-april-2026/> / <https://securityboulevard.com/2026/04/mitre-attck-v19-drops-april-28-how-to-prepare-your-soc-for-the-defense-evasion-split/>
- KEV 主・多シグナル優先度(CISA BOD 26-04 / 合成): <https://www.cybrsecmedia.com/from-cvss-to-kev-cisa-rewrites-federal-patching-priorities/> / <https://www.aptori.com/blog/comparing-nist-lev-epss-and-kev-for-vulnerability-prioritization> / <https://www.picussecurity.com/resource/blog/comparing-cvss-epss-kev-ssvc-lev-and-pxs-from-scores-to-security-proof>
- 決定論 + agentic(Pentera / THN): <https://thehackernews.com/2026/04/deterministic-agentic-ai-architecture.html> / <https://pentera.io/pentera-platform/>
- CTI 潮流 / agentic SOC / AI-to-AI: <https://www.slcyber.io/blog/what-is-cti-the-essential-guide-to-cyber-threat-intelligence-in-2026> / <https://www.marketsandmarkets.com/Market-Reports/agentic-ai-security-market-97017233.html> / <https://www.cyware.com/blog/2026-the-year-when-cyber-threat-intelligence-evolves-into-proactive-ai>
- OASIS STIX/TAXII 2.1 / CVSS 4.0 / LEV / Engage: <https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=cti> / <https://www.first.org/cvss/v4.0/> / <https://csrc.nist.gov/pubs/cswp/41/likely-exploited-vulnerabilities-a-proposed-metric/final> / <https://engage.mitre.org/>
