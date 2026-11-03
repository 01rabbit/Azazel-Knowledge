# ATT&CK v19.2 → v20 内容移行点検 + AI 系技術の追加助言マッピング評価(2026-11)

作成日: 2026-11-03 / 担当: Claude Code(技術偵察) / 対象 main: `09d234c` /
親レポート: [`ai-landscape-2026-11.md`](ai-landscape-2026-11.md) §3.1 の提案 P2(a)/(b) の実施。

> **位置づけ。** 本書は**点検・評価のみ**で、コード・設定・ADR を変更しない。MITRE ATT&CK **v20
> (2026-10-13 出荷、v19.2 を置換)**に対し、(§A)本ノードの ATT&CK 利用面が内容的に陳腐化しないかの
> 棚卸しと、(§B)v20 が新収載した AI 系5技術を追加助言コンテキストとして取り込む価値のスパイク評価を行う。
> 結論は **「v20 への再取り込みは安全・コード/設定変更不要」(§A)**、**「AI 系技術の明示マッピングは現行の
> 証拠ソースでは実需が薄く、据え置きが妥当」(§B)**。いずれも絶対制約1〜8・ADR-0006/0009/0014 を尊重する。

---

## §A. v19.2 → v20 内容移行点検

### A.1 本ノードが ATT&CK を使う3面(実地確認)

| 面 | 実体 | tactic/technique の扱い |
|---|---|---|
| スコアリング寄与 | `config/attack-map.yaml`(6ルール) | **technique_id のみ**を証拠述語から導出(`T1110` / `T1595.002` / `T1071.004` / `T1071.001`×2 / `T1003`)。tactic(TA00xx)は**参照しない** |
| 取り込み(intel-tier) | `src/azazel_knowledge/feeds/adapters/attack.py` → `intel.attack_technique` | ATT&CK STIX を full ingest。各行に `attack_version` を刻印。tactic は `attack/attack_stix.py` の `flatten()` が STIX から動的導出(`tactics: list[str]`) |
| 契約/輸出 | `api/routers/reads.py`(`_attack_version`)/ `config/lite-export-policy.yaml` | `/v1/context` と Lite export が `attack_version` と technique_id + tactics を**取り込み値のまま**提示 |

**重要:** コード・設定に **tactic ID / tactic 名(`TA0005`・"Defense Evasion"・"Stealth" 等)の直書きは存在しない**
(`grep` で確認。ヒットは `docs/reports/*` の過去レポートのみ)。tactic は取り込んだ STIX から流れてくる派生値であり、
`attack_version` に紐づく。

### A.2 v19 Defense Evasion 分割(TA0005→Stealth / TA0112)の影響

- 繰越点検項目だった v19 の Defense Evasion 分割は、**本ノードのマッピング6技術のいずれの tactic にも当たらない**:
  Brute Force(T1110=Credential Access)、Vuln Scanning(T1595.002=Reconnaissance)、DNS/Web C2(T1071.x=Command and
  Control)、OS Credential Dumping(T1003=Credential Access)。**Defense Evasion 配下の技術を1件もマップしていない。**
- tactic 名は取り込み由来のため、v20 を再取り込みすれば**新しい tactic 文字列が自動で流れる**(コード変更不要)。
  これは `/v1/context` と Lite export の**助言メタデータ**に現れる変化であって、スコア値には影響しない。

### A.3 v20 差分の影響(2026-10-13)

- v20 の変更は**加算的**(AI 系5技術 / T1697 MFA 迂回 / T1696 CAPTCHA / T1195.001 更新 / 新規2グループ・2キャンペーン)。
  **本ノードがマップする6技術の廃止・改称は無い**(T1110 / T1595.002 / T1071.004 / T1071.001 / T1003 はいずれも v20 で現役)。
- `attack-map.yaml` は未知 op/version/technique を**ハードフェイルせずスキップ+ログ**する設計(ファイル冒頭コメント)。
  したがって取り込みが進んでも**フェイルクローズドは崩れない**。

### A.4 決定論への影響

- `attack_version` は**スコアリング7要素タプルの一員**(`worker.py:105,274`)。world の ATT&CK 世代が v19.2→v20 に動けば
  **タプルが変わるため、新世代のリプレイは新タプルで別個にバイト同一**になる(旧世代のリプレイも旧タプルで不変)。
  → **②決定論スコアリング・③決定論入力規律は保たれる**。内容移行は決定論規律の変更ではない。

### A.5 §A 結論

- **v20 への再取り込みはコード・設定変更なしで安全。** 移行作業は「ATT&CK フィードの世代を v20 に上げる」運用操作のみで、
  `attack-map.yaml` / `attack_stix.py` / `reads.py` の修正は不要。
- **残る実務注意は1点だけ:** tactic 文字列が取り込み由来で変わる(例: Defense Evasion 系の呼称変更)ため、
  Edge 側・運用者向けドキュメントで tactic 名を**人手で言い換えて固定していないか**だけ確認する(本リポ内には無し)。
- ⑤local.db 不可侵も維持(ATT&CK は intel-tier の full-replace アダプタ経由、local-tier 非破壊)。

---

## §B. v20 AI 系5技術の追加助言マッピング評価(design spike)

### B.1 対象技術と本ノードの証拠ソース

| 技術 | ID | 本質 |
|---|---|---|
| Direct Prompt Injection | T1699 | LLM インタフェースへの直接注入 |
| Indirect Prompt Injection | T1698 | AI が後で処理する内容への隠し注入 |
| AI-Enabled Exfiltration | T1700 | 組織自身の AI エージェントを使った持ち出し |
| AI Result Poisoning | T1608.007 | AI 検索/アシスタントの推薦操作 |
| Impair Autonomous Defenses | T1685.007 | AI 駆動セキュリティ制御の妨害 |

本ノードが Edge から受ける証拠は **EVE アラート・DNS・JA3/JA4・フロー・遅延履歴・reaction**(README/architecture)。
`attack-map.yaml` の述語は正規化済み証拠フィールド(`alert.category`・`alert.proto`・`dns.query_entropy`・
`flow.periodicity_score`・`ioc.matched_ip` 等)上で評価される。

### B.2 評価

- 上記5技術は**AI システムに対する/を使った攻撃**であり、本ノードが受ける**ネットワーク層の証拠では弁別できない**
  (prompt の中身も AI エージェントの挙動も Edge 証拠には現れない)。よって `attack-map.yaml` に新ルールを足す
  **証拠的根拠が現状はない**(足しても `match` が発火しない空ルールになる)。
- 一方、**技術定義そのもの(ラベル・説明・tactic)は、ATT&CK フィードが v20 に進んだ時点で `feeds/adapters/attack.py`
  経由で intel-tier の知識として自動的に取り込まれる**(§A)。すなわち「v20 の AI 技術を知識として持つ」ことは
  **追加作業ゼロで達成**される。運用者が technique を検索・参照する面ではすでに利用可能になる。
- DUSTMAKER 等の観測事例(2026-11 レポート §3.4)が示す T1698 / T1195.001 の脅威は、本ノードの**プロダクト証拠**より
  **開発工程(Codex 委任の worktree/spec)**に当たる。これは本月 P3 で `development-guide.md` §2C に明文化済みで、
  プロダクト側のマッピングでは対処しない。

### B.3 §B 結論(据え置き + 将来条件)

- **明示マッピングは据え置き。** 現行の証拠ソースでは発火しないため、`attack-map.yaml` への AI 技術追加は行わない。
  v20 定義の知識取り込みは自動で足りる。
- **将来の採用条件(demand-gated):** Edge が prompt-injection 兆候を弁別できる証拠(例: LLM 公開サービスのペイロード検査結果)を
  **新たな証拠契約として**送るようになった場合に限り、追加助言ルールを検討する。その場合も **(i) technique_id のみ /
  (ii) `attack_version` 刻印 / (iii) 非属性文面(「AI 悪用 TTP に対応し得る」止まり、AI 使用の証明にしない=ADR-0009)/
  (iv) intel-tier full-replace・local.db 非破壊**を厳守する。
- **エスカレーション境界:** これらを万一でも**スコア入力**(7要素タプルや重み)に接続する案は、F-2/F-8(byte-identical replay)と
  ADR-0006 を破壊するため**新 ADR 必須**。本評価の範囲では**非推奨**とし、マスター判断に委ねる。

---

## 付記: 絶対制約との整合(本点検・評価の自己監査)

- ①助言専用 / ⑧助言ルールのみ: 本書は点検・評価のみ。マッピング追加もスコア化もしていない。
- ②決定論 / ③入力規律: `attack_version` が7要素タプルの一員である事実を再確認(A.4)。移行は決定論規律を変えない。
- ⑤local.db 不可侵: ATT&CK は intel-tier full-replace。local-tier に触れない(A.5)。
- ⑦依存最小性: 新規依存なし(stdlib + PyYAML + idna + PyNaCl、Fabric は api/taxii extra 限定)。
- **指摘ゼロでも「なぜ問題ないか」:** v20 は加算的で既存6技術の廃止が無く、tactic は取り込み由来・`attack_version` 刻印のため、
  内容移行はドキュメント言い換えの確認のみで閉じる。AI 技術は証拠ソース不一致により現状はスコア化不能で、知識取り込みは自動。
</content>
