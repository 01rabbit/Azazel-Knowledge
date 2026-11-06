# Azazel-Knowledge(旧 Azazel-CTI)開発指示書 — MacBook 環境(Claude Code 指揮 × Codex 実装)

作成日: 2026-07-06 / 対象: `01rabbit/Azazel-Knowledge` main(PR #15 マージ後)

---

## 0. 現状分析

### main に入っているもの(Phase 1 + Phase 2 Behavioral CTI、現行基準線テスト合格)

- 5巡の敵対的設計レビューを経た最終設計 `docs/design/phase1-implementation.md`(修正登録簿 F-1〜F-20 付き。以後「設計書」)
- Phase 1 実装一式: `src/azazel_knowledge/`(api / core / db / normalize / feeds / ingest / correlate / scoring / recommend / rules / patterns / reactions / attack / bundle / security / audit / taxii)、`worker.py`、`azctl`、`tools/`、`ops/`、`docs/operations.md`、`tests/unit`
- Phase 2 **Behavioral CTI**(issue #31〜#37、設計 `docs/design/phase2-implementation.md` の F2-1〜F2-20、[ADR-0009](adr/0009-behavioral-cti.md)): 行動パターン schema(`migrations/local/0002_behavior.sql`)、決定論生成器(`patterns/behavior_generate.py` + P2 + `azctl behavior`)、類似度/再現性(`scoring/behavior_similarity.py`)、friction timeline レポート(`reports/` + `reads.py`)、`/v1/context` の `behavioral_cti` ブロック、reaction ペイロード拡張(`0003_reaction_ext.sql`)、shadow scoring(`scoring/behavior_shadow.py`、default-off)
- テスト基準線: 通常API依存は公開stable Fabric v0.10.0 (ADR-0023)。Knowledge Contextの隔離試験も同じtagで実施し (ADR-0024)、**現在 = 1802** collected。

> **基準線テスト数の単一情報源は `CLAUDE.md`**(§git 規律 / §検証コマンド / §リポジトリ地図)。
> 本書は**正を名乗らない**。かつて本書が「唯一の正」を名乗って 591、`AGENTS.md` が 487、
> `CLAUDE.md` が別の値を掲げ、三重に食い違った。正を分散させたことが原因である。
> 本書で「現行基準線」と言えば直上の現在値を指し、それは `CLAUDE.md` の再掲である
> (`python -m pytest tests/unit -q` 実測)。基準線が動いたら
> **`CLAUDE.md`・本書・`AGENTS.md` を同じ差分で更新する**。三文書の一致と実測値との整合は
> `tests/unit/test_claude_md_baseline.py` が機械的に強制し、1箇所でも古ければ赤になる。
> 本書の他所は数値を直書きせず「現行基準線」と参照する
> (生モノの分散を防ぐ / 2026-08 技術偵察レポート P1)。
> **フロンティアモデルの具体名(Claude / Codex 側の推奨世代)も同様に生モノ**であり、本書には
> 直書きしない。最新の推奨世代は月次の [`docs/reports/ai-landscape-*.md`](reports/) 最新号を単一情報源とする。

### 完了タスク(Phase 1 整備 T1〜T6)

| # | タスク | 状態 |
| --- | --- | --- |
| T1 | GitHub Actions CI | ✅ 完了(pytest + check-config が全 PR で緑) |
| T2 | `tools/docs-sync-check.py` 本実装 | ✅ 完了 |
| T3 | 文書批准差分(data-model.md / scoring.md / api.md) | ✅ 完了(オーナー批准済み) |
| T4 | `tools/bench/` S9性能ゲートハーネス | ✅ 開発完了(実機実行は下記の残項目) |
| T5 | Issue 整理・クローズ | ✅ Phase 1/2 の子 Issue はクローズ済み |
| T6 | S13持ち越し(GenCache / RLIMIT_AS・cgroup / zstd化) | ✅ 計測完了(`tools/bench/compression_bench.py` ほか、zstd 不採用寄りで記録) |

### 残タスク(= 今後の開発対象)

| # | タスク | MacBookで可能か |
| --- | --- | --- |
| — | Pi 4 実機での性能ゲート実行(S9)、LUKS/Adiantum検証 | ×(実機必須。issue #21) |
| — | Edge側SLO確認(220msブレーカー、advisory_idエコー)、Behavioral CTI 用 reaction ペイロード送信([Azazel-Edge#305](https://github.com/01rabbit/Azazel-Edge/issues/305)) | ×(Azazel-Edge側判断) |
| — | roadmap Phase 2 のスケール項目(cross-edge 相関、multi-edge ingest、SQLite→Postgres 評価) | ○ |
| — | ~~[Azazel-Fabric](https://github.com/01rabbit/Azazel-Fabric)(旧 Azazel-Common、`azazel_fabric.cti_contracts`)の採用可否評価~~ **完了**: [ADR-0010](adr/0010-adopt-fabric-cti-contracts.md)(2026-07-10)で `api` extra 限定・タグ固定として採用済み(境界のみ・追加的・wire shape 不変)。現行ピンは **v0.10.0**([ADR-0023](adr/0023-fabric-pin-v0-10-0.md)・`pyproject.toml`、正式版) | ○(完了) |

### 絶対制約(全タスクの受け入れ基準。違反はレビューで即差し戻し)

絶対制約は `CLAUDE.md` の「絶対制約1〜8」を唯一の正とする(各項に強制手段=静的テスト名を併記)。
本書ではこれ以上再掲しない(二重管理を避けるため)。以降で「絶対制約」と言えば
CLAUDE.md の 1〜8 を指す。

---

## 1. MacBook 環境構築手順

```bash
# 1) 基本ツール(Homebrew 導入済み前提)
brew install python@3.11 git gh
# Docker が必要な場合(ops/docker-compose.yml の検証用。任意)
brew install --cask orbstack   # または docker-desktop

# 2) リポジトリ取得
gh auth login
git clone https://github.com/01rabbit/Azazel-Knowledge.git
cd Azazel-Knowledge

# 3) Python 環境(venv 必須。システムPythonに直接入れない)
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[api,dev]"

# 4) 健全性確認(ここが緑になるまで先に進まない)
python -m pytest tests/unit -q          # 期待値: 現行基準線が全て passed(本数は §0 の単一情報源を参照)
python azctl check-config --config-dir config   # メモリ算術が OK と出ること

# 5) スモーク(任意だが推奨)
mkdir -p /tmp/azctl-smoke && cd /tmp/azctl-smoke
PYTHONPATH=~/path/to/Azazel-Knowledge/src python ~/path/to/Azazel-Knowledge/azctl provision
cd -
```

### Dev run — E2E harness(app + worker、AZ-06 deception-effectiveness / ADR-0011)

For isolated Nexus Knowledge Context software tests, install
`.[api-context-candidate,dev]` instead of `.[api,dev]`. Do not combine the extras.
Both dependency profiles use the exact published stable Fabric v0.10.0 tag;
the contract profile remains experimental and optional. This test setup is not
a production credential, network, or service activation guide.

virtual E2E で Deception→Edge→Knowledge を localhost で噛み合わせる際の最小起動手順。
`api` extra(fastapi/uvicorn/pydantic/azazel-fabric)を入れた venv 前提。Fabric の
現行ピンは **v0.10.0**([ADR-0023](adr/0023-fabric-pin-v0-10-0.md))で、正式版(stable)タグです。
`pip install -e '.[api,dev]'` がタグから解決するので、editable の Fabric は不要:

```bash
pip install -e '.[api,dev]'                    # azazel-fabric 0.10.0 をタグから解決

# 1) ノードを provision(local.db + intel gen-1 + 署名鍵 + admin client)
ROOT=/tmp/az-dev-root
python azctl provision --root "$ROOT"
export AZAZEL_ROOT="$ROOT" AZAZEL_CONFIG_DIR="$PWD/config"

# 2) ingest+read スコープの client トークンを発行(1回だけ表示される)
python azctl client add --root "$ROOT" --key-id edge1 --scopes ingest,read
TOK=azcti_edge1_...        # 上で表示された token を控える

# 3) API を起動(別ターミナル)。ハンドラは sync def → uvicorn の threadpool へ
python -m uvicorn azazel_knowledge.api.app:app --host 127.0.0.1 --port 8099

# 4) worker を起動(別ターミナル)。単一ライタ。--once で1サイクル、無指定で常駐
python -m azazel_knowledge.worker --root "$ROOT" --config-dir "$AZAZEL_CONFIG_DIR"
#   （バッチ投入のたびに drain したいだけなら `--once` を都度実行でもよい）
```

サンプル: InteractionObservation バッチを POST → worker が drain → advisory を GET。

```bash
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
curl -s -X POST http://127.0.0.1:8099/v1/deception-observations \
  -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -d '{"environment_id":"env-1","items":[
        {"observation_id":"o1","environment_id":"env-1","package_id":"pkg-1","node_id":"node-1","observed_at":"'"$TS"'","observation_class":"interaction","surface":"service"},
        {"observation_id":"o2","environment_id":"env-1","package_id":"pkg-1","node_id":"node-1","observed_at":"'"$TS"'","observation_class":"reaction","surface":"credential_lure","reaction_kind":"authenticate","confounder_tags":["scanner_noise"]},
        {"observation_id":"o3","environment_id":"env-1","package_id":"pkg-1","node_id":"node-1","observed_at":"'"$TS"'","observation_class":"outcome","surface":"file","reaction_kind":"exfiltrate"}
      ]}'
# → 202 {"batch_id": "..."}   （fire-and-forget: 受理時に中身は検証しない）

# worker が P1 で drain した後（常駐なら数秒、--once なら実行後):
curl -s "http://127.0.0.1:8099/v1/deception-effectiveness?environment_id=env-1" \
  -H "Authorization: Bearer $TOK" | python -m json.tool
# → EffectivenessAdvisory(advisory_only / executable:false / confidence / counter_evidence / unknowns)
```

同一入力なら advisory はバイト同一(F-2 リプレイ規律)。timeout は `503 context_timeout`、
監査チェーン書込失敗は `503 audit_unavailable` でフェイルクローズド(F-12/F-17)。

### VS Code セットアップ

```bash
brew install --cask visual-studio-code
code .   # リポジトリを開く

# 拡張機能(VS Code 内からインストール)
#  - Anthropic: Claude Code / Claude Code for VS Code
#  - OpenAI: Codex(または `npm i -g @openai/codex` で CLI 併用)
#  - ms-python.python, charliermarsh.ruff(任意)

# CLI 併用の場合
npm install -g @anthropic-ai/claude-code && claude   # /login で認証
npm install -g @openai/codex && codex                # 認証
```

VS Code 設定(`.vscode/settings.json` 推奨):

```json
{
  "python.defaultInterpreterPath": "${workspaceFolder}/.venv/bin/python",
  "python.testing.pytestEnabled": true,
  "python.testing.pytestArgs": ["tests/unit", "-q"]
}
```

---

## 2. 運用体制 — Claude Code が指揮、Codex が実装

役割分担は Phase 1 と同じ「指揮・敵対的レビュー」と「実装労働」の分離を人間+2AIで再現する。
受け渡しの実装方式は2つあり、まず **Option A(手動リレー)** で感触を掴み、慣れたら
**Option B(Codex CLI を Bash 配線)** で半自動化する。両者は同じ役割図・同じ憲法で動く。

- **Option A(手動リレー)**: Claude Code が書いた仕様をあなたが Codex に貼り、実装差分を
  Claude Code に戻してレビューさせる。確実だがあなたが伝令になる。下図がこの形。
- **Option B(Bash 配線)**: Claude Code が `codex exec` を Bash 経由で直接呼び、
  出力を受け取ってレビューまで自走する。本当の"サブエージェント"に一番近い(§2B)。

```text
あなた(マスター) ──指示──▶ Claude Code(指揮官)
                              │ 1. タスクを仕様化(受け入れ基準+絶対制約を明記)
                              │ 2. AGENTS.md 経由で Codex に実装指示
                              ▼
                          Codex(実装者) ─ ブランチ上で実装、テスト緑まで
                              ▼
                       Claude Code(敵対的レビュー)
                              │ 差分を絶対制約1〜8(CLAUDE.md)+設計書と突き合わせて攻撃
                              │ 指摘 → Codex 修正 → 再レビュー(緑まで反復)
                              ▼
                       コミット/プッシュ/PR(Claude Code が担当)
```

#### 鉄則

- Codex への指示には必ず「対象ファイル所有権」「受け入れ基準」「絶対制約」を含める(曖昧な指示を出さない)
- レビューは最低1回の敵対的パス(指摘ゼロでも「なぜ問題ないか」を書かせる)
- `main` 直接コミット禁止。1タスク=1ブランチ=1PR
- 現行基準線のテスト(§0 の単一情報源を参照)を1本でも壊した状態でのコミット禁止
- 設計書と矛盾する実装が必要になったら、実装で黙って変えず、設計書の改訂を同じPRに含めて明示する

---

## 2B. Option B: Codex CLI を Bash ツールとして配線する

Claude Code(指揮官)が `codex exec`(Codex の非対話実行モード)を Bash 経由で直接呼び、
実装差分を受け取ってそのままレビュー・テストへ回す半自動ループ。指示書の体制を人手リレー
なしで回せる。ただし **2つの frontier エージェントが同一リポジトリを触る**ため、
worktree 分離と権限制御を先に固めること。

### 前提(一度だけ)

```bash
# Codex CLI 導入と認証(ChatGPT サインイン か OPENAI_API_KEY のどちらか)
npm install -g @openai/codex
codex login                         # または: export OPENAI_API_KEY=sk-...
codex exec --help                   # exec(非対話)サブコマンドがあることを確認
```

Codex 側のデフォルト設定 `~/.codex/config.toml`(任意だが推奨):

```toml
# 非対話実行での既定を安全側に固定
approval_policy = "never"           # exec は対話承認を出さない前提で回す
sandbox_mode    = "workspace-write" # 作業ツリー内の書き込みのみ許可(full-access は使わない)
# network はデフォルト制限。pip 等が要るなら venv を事前構築しておく(下記)
```

### 権限許可リスト設定(Claude Code 側)

Claude Code が毎回プロンプトを出さずに `codex exec` を叩けるよう、プロジェクトの
`.claude/settings.json` に**前置マッチで狭く**許可を入れる。`danger-full-access` は
許可リストに**入れない**(サンドボックス逸脱を機械的に禁止)。

```jsonc
{
  "permissions": {
    "allow": [
      "Bash(codex exec:*)",           // 非対話実行のみ許可
      "Bash(git worktree:*)",         // worktree の作成/削除
      "Bash(python -m pytest:*)"      // レビュー時のテスト実行
    ],
    "deny": [
      "Bash(codex exec --sandbox danger-full-access:*)",  // 逸脱を明示拒否
      "Bash(codex exec --dangerously-bypass-approvals-and-sandbox:*)"
    ]
  }
}
```

> 注: `deny` は `allow` に優先する。full-access 系フラグを明示拒否しておくと、
> Codex 側の設定が緩くても Claude Code からは危険モードで起動できない。

### worktree 分離ルール(必須)

Claude Code の作業ツリーと Codex の作業ツリーを**物理的に分ける**。同じディレクトリを
2エージェントが同時に書くと確実に壊れる。1タスク=1 worktree=1ブランチ。

```bash
# Claude Code がタスク開始時に作る(リポジトリ隣に隔離コピー)
git worktree add ../azazel-codex/<task> -b <branch> origin/main

# Codex 用に venv を事前構築(network 制限下でも pip 済みにしておく)
cd ../azazel-codex/<task>
python3.11 -m venv .venv && . .venv/bin/activate && pip install -e ".[api,dev]"
cd -

# タスク完了・マージ後に掃除
git worktree remove ../azazel-codex/<task>
```

- Codex には常に `--cd ../azazel-codex/<task>` でこの worktree を渡す
- Claude Code 本体のツリーでは **git 操作とレビューのみ**。実装ファイルは worktree 側だけを変更
- 複数タスクを並行させるなら worktree も人数分。`<task>` 名は衝突させない

### `codex exec` 呼び出し規約(Claude Code が守る)

```bash
codex exec \
  --cd ../azazel-codex/<task> \        # 隔離 worktree を作業対象に
  --sandbox workspace-write \          # ツリー内書き込みのみ(full-access 禁止)
  --model <codex-model> \              # 実装向けモデルを明示(現行推奨世代は docs/reports/ai-landscape-*.md 最新号を参照)
  "$(cat spec.md)"                     # 仕様は AGENTS.md 準拠のスペックを渡す
```

規約:

1. **仕様は必ずファイル(`spec.md`)経由**で渡す。「所有ファイル・受け入れ基準・絶対制約1〜8・
   テスト要件」を含め、口頭要約で投げない(AGENTS.md が worktree にあるので Codex は自動で読む)
2. `codex exec` の**標準出力(最終メッセージ)をログに残す**。Claude Code はそれと
   `git -C ../azazel-codex/<task> diff` の両方を突き合わせてレビューする
3. Codex に **git コミット/プッシュをさせない**。コミット・プッシュ・PR は Claude Code が
   worktree の差分を検証してから本体側で行う(権限と履歴の一元管理)
4. ネットワークが要る作業(新規 pip 依存など)は原則禁止。必要なら Claude Code が
   worktree 側で事前に用意し、Codex はオフラインで実装する(オフラインファースト教義とも一致)
5. 1回の `codex exec` で閉じない場合は、Claude Code のレビュー指摘を追記した spec で
   **同じ worktree に対して再度 `codex exec`**(会話継続ではなく差分指示の反復)

> **注記(Claude Code ネイティブ subagents による Option B 置換の評価)。** Claude Code の
> Dynamic Workflows / Performance Outcomes(採点役が合格まで差し戻すループ)/ ネイティブ
> subagents は、本書の Option B(外部 Codex 実装 + 敵対的レビュー・ループ)の**機構的相似形**であり、
> 実装も Claude Code 単体で回せる代替候補になりうる。ただし現行体制が **OpenAI Codex を別ベンダの
> 実装者として併用**するのは、「指揮官と実装者を別モデルにして写経レビューを避ける」**意図的な
> 敵対的多様性**であり、単純な機能置換で捨てない。採否は ADR 相当の判断を要する別タスクとして
> 評価し、**本注記の時点では即時変更しない**(2026-08 技術偵察レポート P1)。置換を評価する場合も、
> ネイティブ subagents 併用時は本 §2B の権限制御(`codex exec` 前置マッチ許可 + `danger-full-access`
> 明示拒否 + worktree 分離)と同じ「サンドボックス逸脱を機械的に禁止」原則を延長する。

### 半自動ループ(Claude Code の手順テンプレ)

```text
1. git worktree add + venv 構築(隔離)
2. spec.md 生成(§4 のタスク指示 + 絶対制約 + 所有ファイル + テスト要件)
3. codex exec --cd <wt> --sandbox workspace-write "$(cat spec.md)"  → 出力をログ
4. python -m pytest tests/unit -q を worktree で実行
5. 敵対的レビュー(§5 チェックリスト)を diff に対して実施
6. 指摘あり → spec に追記して 3 へ / 全緑かつ指摘なし → 7
7. Claude Code 本体で差分を取り込みコミット・プッシュ・ドラフトPR
8. マージ後 git worktree remove で掃除
```

### コストと停止条件

- Codex は別課金。`codex exec` を回すほど OpenAI 側の消費が増える。**空回りループを防ぐ**ため、
  同一 spec での再実行は上限(例: 3回)を決め、超えたら Claude Code がマスターに要判断で止める
- Codex がサンドボックス外を触ろうとした/network を要求した場合は**即中断**し、
  タスクを Option A(手動)に落とすかスコープを切り直す

---

## 2C. 開発ツールチェーンの供給網衛生(外部 MCP / エージェント拡張)

開発時に Claude Code / Codex へ**外部 MCP サーバやエージェント拡張**を接続する場合の最小衛生を定める。
これは**開発工程側**の規律であり、**プロダクト(`src/azazel_knowledge/`)の攻撃面ではない**——
本ノードのランタイムは MCP を使わず、コア依存は stdlib + PyYAML + idna + PyNaCl のみ、Fabric も
`api` extra 限定(ADR-0010)。offline-first・依存最小性の精神を開発工程側へ延長する
(2026-08 技術偵察レポート P4)。

- **許可リスト運用。** 接続してよい MCP サーバは**署名・アテステーション・版固定つきの許可リスト**で
  管理し、**新規サーバ登録=変更管理イベント**として扱う(レビューを経ずに繋がない)。
- **認可。** OAuth/OIDC 前提のサーバを優先し、**RFC 9207 の `iss` 検証**(ミックスアップ攻撃緩和)を
  満たすクライアント設定を用いる。仕様は [MCP 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28) を基準とする。
- **ネットワーク遮断の一貫性。** Codex は `--sandbox workspace-write` 固定・network 要求は即中断(§2B)。
  MCP サーバ経由の外部取得も同じ規律で、クエリパス相当の作業に online 依存を持ち込まない。
- **SDK 版追随。** MCP SDK / クライアントは既知脆弱性(供給網 RCE・tool poisoning・token passthrough・
  SSRF・confused deputy 等)に対して版を追随する。参考: [Wiz MCP セキュリティ](https://www.wiz.io/academy/ai-security/model-context-protocol-security) /
  [NSA CSI: MCP Security](https://www.nsa.gov/Portals/75/documents/Cybersecurity/CSI_MCP_SECURITY.pdf)。
- **注入文の混入防止(供給網 × indirect prompt injection)。** `spec.md`・worktree 内の `AGENTS.md`・
  Codex から取り込む差分・外部由来の資料に、**信頼できない注入文(indirect prompt injection)**が
  混ざっていないことをレビュー時に確認する。MITRE ATT&CK v20 は Indirect Prompt Injection(**T1698**)と
  開発環境/AI コーディングエージェント設定ファイルを狙う供給網(**T1195.001**)を収載し、Google GTIG は
  設定ファイルやローダのコメントにプロンプトを埋めてスキャナを回避するマルウェア(DUSTMAKER)や
  **AI 開発者設定を標的とするインフォスティーラ**を報告した(2026-11 レポート §3.4)。本面は既存の
  `--sandbox workspace-write` 固定・network 要求即中断・許可リスト運用(§2B)が機械的に緩和しているため、
  ここでは**レビュー観点の明文化**にとどめる。
- **Claude Code / Codex の新機能整合(2026-11)。** (a) Claude Code の**背景エージェントによるドラフト PR 起票**は
  本書の git 規律(PR はドラフトで作成)と噛み合う運用経路であり、月次偵察・保守タスクはこの形で提出してよい。
  (b) **Claude in Chrome(GA)**等のブラウザ機能は開発補助に限り、**プロダクトのクエリパス検証には使わない**
  (offline-first の一貫性)。(c) Codex CLI の **enterprise MCP 認証拡張**は上記「認可」の許可リスト運用の範囲内で扱う。
  最新の推奨モデル世代は §0 の単一情報源([`docs/reports/ai-landscape-*.md`](reports/) 最新号)に委譲する。
- **プロダクトへの MCP 導入は現時点で行わない。** 助言 API を MCP サーバとして公開する等は
  攻撃面・依存増を招くため据え置き(覆すなら ADR 案件。2026-08 レポート §5)。

---

## 3. 規範ファイル(初回セットアップ時に作成済み)

指揮官/実装者の規範はリポジトリ直下の実ファイルが唯一の正。本書はテンプレを再掲しない。

- **`CLAUDE.md`** — Claude Code(指揮官)の規範。絶対制約1〜8・委任プロトコル・敵対的レビュー
  チェックリスト・git 規律の正本。
- **`AGENTS.md`** — Codex(実装者)の規範。worktree 内で Codex が自動で読む。

> 初回はこの2ファイルを作成済み。以降は実ファイルを直接編集し、本書ではメンテしない。

---

## 4. タスク別開発指示(Claude Code に順番に渡す)

> 各指示はそのまま Claude Code へのプロンプトとして使える。Claude Code はこれを
> Codex 向け仕様に落とし、実装→敵対的レビュー→修正→再レビューまで回すこと。

### T1: GitHub Actions CI(最優先・小)

```text
ブランチ ci/github-actions を切り、Codex に .github/workflows/test.yml を実装させよ。
要件: push/PR で ubuntu-latest + python3.11、pip install -e ".[api,dev]"、
python -m pytest tests/unit -q を実行。concurrency で同一refの多重実行をキャンセル。
所要3分以内に収まること。加えて azctl check-config --config-dir config を実行する
ジョブを含める。敵対的レビュー観点: キャッシュ毒性(actions/cache のキー設計)、
fork PR での secrets 非使用、pip の固定(ハッシュまでは不要、メジャー固定で可)。
完了後ドラフトPRを作成。
```

### T2: docs-sync-check.py 本実装(中)

```text
ブランチ tools/docs-sync-check を切り、Codex に tools/docs-sync-check.py を実装させよ。
仕様(設計書 S5/S12): config/scoring.yaml の weights / confidence_weights /
freshness 値と、docs/scoring.md・docs/api.md 内の数値例・重み表を突き合わせ、
不一致を exit 1 + 差分レポートで報告する。docs/design/phase1-implementation.md の
批准待ち差分リスト(A-label IDN、重み表、KEV sources[])は「既知の未批准差分」として
allowlist ファイル(tools/docs-sync-allowlist.yaml)で管理し、それ以外の不一致のみ fail。
tests/unit/test_docs_sync.py を追加。T1 の CI にステップとして組み込む(allowlist が
ある間は警告表示、空になったら fail に昇格する2段階動作)。
```

### T3: 文書批准差分PR(中・オーナー判断材料)

```text
ブランチ docs/ratification を切り、Codex に以下の文書改訂を作らせよ(コード変更なし):
1. docs/data-model.md: IOC正規化を U-label → A-label 正準形へ改訂(F-15。ホモグリフ
   耐性の根拠1段落を追加)
2. docs/scoring.md: 実装済み重み表(ioc_match .30 / history .20 / attack_map .15 /
   cve_exploited .15 / campaign .10 / geo_asn .10)と confidence 4ドライバ式へ更新、
   cve_exploited の applies_when 再正規化の説明を追加
3. docs/api.md: /v1/context 応答例を実装契約(confidence_reason[]、multi_ioc_scope、
   advisory_id)に一致させ、reason[] 例の算術を重み表と整合させる
各差分に「設計書 §12 のどの批准項目に対応するか」を PR 説明で明記。これは
オーナー批准用の PR なので、マージ判断はマスターに委ねる旨を PR 冒頭に書く。
完了後 T2 の allowlist から該当項目を削除する準備(コメントアウト)もしておく。
```

### T4: S9 性能ゲートハーネス(中〜大。実行は Pi 4、開発は Mac)

```text
ブランチ perf/bench-harness を切り、Codex に tools/bench/ を実装させよ。
設計書 S9 のゲートをスクリプト化する:
1. capacity_run.py — ブレーカー無効で lookup p95 / context p95 を測る(合成 10M IOC
   生成器 tools/bench/synth_dataset.py を含む。Mac では --scale 0.01 で dry-run)
2. availability_run.py — ブレーカー有効で 503 率を測る(基準負荷と2倍負荷)
3. cold_read.py — posix_fadvise(DONTNEED) 強制コールドリードのマイクロベンチ
4. run_all.sh — Pi 4 上での実行手順(LUKS/Adiantum 前提)を ops/hardware-profile.md
   への参照付きで整備。結果は JSON で bench-results/ に出力し、ゲート閾値
   (50ms/250ms/0.5%/2%/ヘッドルーム20%)との合否を明示
Mac では機能テスト(小規模データでの正動作)のみ tests/unit/test_bench.py で保証し、
「Mac の数値は参考値であり合否判定に使わない」ことをツール出力に明記させる。
```

### T5: Issue 整理(小・GitHub操作のみ)

```text
Issue #12 の子Issue #1〜#11 それぞれについて、PR #15 の実装がどのファイル/テストで
受け入れ基準を満たしたかをコメントで対応表として記録し、満たしたものはクローズ提案
(クローズ自体はマスター承認後)。#14 も完遂済みなのでクローズ提案に含める。
未達部分(例: #10 の実機 provisioning 検証、#11 の実機手順検証)は新しい
「Pi 4 hardware validation」Issue に切り出して集約する。
```

### T6: S13 持ち越し検討(低優先・設計判断が必要なものは実装前にマスター確認)

```text
以下は実装前に必ずマスターに選択肢を提示すること(勝手に実装しない):
- 共有メモリ GenCache(3×64MB 重複の解消)— multiprocessing.shared_memory 案の設計スパイク
- バンドル zstd 化 — zstandard 依存追加の是非(ADR 追記が必要)
- RLIMIT_AS vs cgroup ギャップの計測スクリプト
```

---

## 5. 敵対的レビューチェックリスト

毎PRで使うチェックリストは `CLAUDE.md` の「敵対的レビューチェックリスト」を唯一の正とする
(絶対制約1〜8対応・テスト基準線・依存追加の扱いを含む)。本書では再掲しない。

---

## 6. 最初の1時間でやること(チェックリスト)

1. [ ] §1 の環境構築 → 現行基準線テスト緑を確認(本数は §0 の単一情報源を参照)
2. [ ] VS Code + Claude Code + Codex の認証確認(`codex login` 済みも確認)
3. [ ] Claude Code に §3 の CLAUDE.md / AGENTS.md を作成させ、最初のコミット(ブランチ chore/agent-guides)
4. [ ] まず **Option A(手動リレー)** で T1(CI)を1本通す — 体制の感触を掴む最小タスク
5. [ ] 慣れたら §2B の **Option B** を配線(`.claude/settings.json` 許可リスト + worktree 分離)
6. [ ] 以後 T2 → T3 → T4 の順に1タスク1PR(1worktree)で進める
