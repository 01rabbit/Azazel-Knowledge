# Azazel-CTI 開発指示書 — MacBook 環境(Claude Code 指揮 × Codex 実装)

作成日: 2026-07-06 / 対象: `01rabbit/Azazel-CTI` main(PR #15 マージ後)

---

## 0. 現状分析

### main に入っているもの(PR #15、487テスト合格)

- 5巡の敵対的設計レビューを経た最終設計 `docs/design/phase1-implementation.md`(修正登録簿 F-1〜F-20 付き。以後「設計書」)
- Phase 1 実装一式: `src/azazel_cti/`(api / core / db / normalize / feeds / ingest / correlate / scoring / recommend / rules / patterns / reactions / attack / bundle / security / audit / taxii)、`worker.py`、`azctl`、`tools/`、`ops/`、`docs/operations.md`、`tests/unit`(487)

### 残タスク(= 今後の開発対象)

| # | タスク | MacBookで可能か |
|---|---|---|
| T1 | GitHub Actions CI(現在 `.github/` が存在しない) | ○ |
| T2 | `tools/docs-sync-check.py` 本実装(設計書S13で持ち越したスタブ) | ○ |
| T3 | 文書批准差分の作成(A-label IDN → data-model.md、重み表 → scoring.md、KEV `sources[]`/`rejected_alternatives` → api.md)→ オーナー批准用PR | ○ |
| T4 | `tools/bench/` S9性能ゲートハーネス(実行は Pi 4、**開発と dry-run は Mac で可能**) | ○(実行は実機) |
| T5 | Issue #12 の子Issue(#1〜#11)の消化確認とクローズ整理 | ○ |
| T6 | S13持ち越し: 共有メモリGenCache、RLIMIT_AS/cgroupギャップ、zstd化の検討 | ○ |
| — | Pi 4 実機での性能ゲート実行(S9)、LUKS/Adiantum検証 | ×(実機必須) |
| — | Edge側SLO確認(220msブレーカー、advisory_idエコー) | ×(Azazel-Edge側判断) |

### 絶対制約(全タスクの受け入れ基準。違反はレビューで即差し戻し)

1. **助言専用** — CTIノードはEdgeに命令しない。api/taxii に書き込みSQLを追加しない(静的テストが監視)
2. **決定論スコアリング** — YAML重み(合計1.0)、`reason[]` 完全性(0寄与も明示)、7要素タプルでバイト同一リプレイ
3. **オフラインファースト** — クエリパスにインターネット依存を持ち込まない
4. **local.db(研究データ)は不可侵** — バンドル/世代スワップが reaction/observation に触れる変更は禁止(F-1)
5. **フェイルクローズド** — timeout は非スコア503、監査不能時は503(F-12/F-17)
6. コア依存は stdlib + PyYAML + idna + PyNaCl のみ(fastapi/pydantic は api/ 限定)

---

## 1. MacBook 環境構築手順

```bash
# 1) 基本ツール(Homebrew 導入済み前提)
brew install python@3.11 git gh
# Docker が必要な場合(ops/docker-compose.yml の検証用。任意)
brew install --cask orbstack   # または docker-desktop

# 2) リポジトリ取得
gh auth login
git clone https://github.com/01rabbit/Azazel-CTI.git
cd Azazel-CTI

# 3) Python 環境(venv 必須。システムPythonに直接入れない)
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[api,dev]"

# 4) 健全性確認(ここが緑になるまで先に進まない)
python -m pytest tests/unit -q          # 期待値: 487 passed
python azctl check-config --config-dir config   # メモリ算術が OK と出ること

# 5) スモーク(任意だが推奨)
mkdir -p /tmp/azctl-smoke && cd /tmp/azctl-smoke
PYTHONPATH=~/path/to/Azazel-CTI/src python ~/path/to/Azazel-CTI/azctl provision
cd -
```

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

```
あなた(マスター) ──指示──▶ Claude Code(指揮官)
                              │ 1. タスクを仕様化(受け入れ基準+絶対制約を明記)
                              │ 2. AGENTS.md 経由で Codex に実装指示
                              ▼
                          Codex(実装者) ─ ブランチ上で実装、テスト緑まで
                              ▼
                       Claude Code(敵対的レビュー)
                              │ 差分を絶対制約1〜6+設計書と突き合わせて攻撃
                              │ 指摘 → Codex 修正 → 再レビュー(緑まで反復)
                              ▼
                       コミット/プッシュ/PR(Claude Code が担当)
```

**鉄則**
- Codex への指示には必ず「対象ファイル所有権」「受け入れ基準」「絶対制約」を含める(曖昧な指示を出さない)
- レビューは最低1回の敵対的パス(指摘ゼロでも「なぜ問題ないか」を書かせる)
- `main` 直接コミット禁止。1タスク=1ブランチ=1PR
- テスト487本を1本でも壊した状態でのコミット禁止
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
  --model <codex-model> \              # 実装向けモデルを明示
  "$(cat spec.md)"                     # 仕様は AGENTS.md 準拠のスペックを渡す
```

規約:
1. **仕様は必ずファイル(`spec.md`)経由**で渡す。「所有ファイル・受け入れ基準・絶対制約1〜6・
   テスト要件」を含め、口頭要約で投げない(AGENTS.md が worktree にあるので Codex は自動で読む)
2. `codex exec` の**標準出力(最終メッセージ)をログに残す**。Claude Code はそれと
   `git -C ../azazel-codex/<task> diff` の両方を突き合わせてレビューする
3. Codex に **git コミット/プッシュをさせない**。コミット・プッシュ・PR は Claude Code が
   worktree の差分を検証してから本体側で行う(権限と履歴の一元管理)
4. ネットワークが要る作業(新規 pip 依存など)は原則禁止。必要なら Claude Code が
   worktree 側で事前に用意し、Codex はオフラインで実装する(オフラインファースト教義とも一致)
5. 1回の `codex exec` で閉じない場合は、Claude Code のレビュー指摘を追記した spec で
   **同じ worktree に対して再度 `codex exec`**(会話継続ではなく差分指示の反復)

### 半自動ループ(Claude Code の手順テンプレ)

```
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

## 3. リポジトリに置くファイル(初回セットアップ時に Claude Code に作らせる)

### 3-1. `CLAUDE.md`(Claude Code = 指揮官の規範)

```markdown
# CLAUDE.md — Azazel-CTI

あなたはこのリポジトリの指揮官兼敵対的レビュアーである。実装労働は Codex に委任し、
自分では原則コードを書かない(仕様化・レビュー・統合判断・git 操作が仕事)。

## 必読
- docs/design/phase1-implementation.md(最終設計。F-1〜F-20 は既決事項)
- docs/adr/*.md(既決の設計判断。覆すには新ADRが必要)
- README.md / docs/architecture.md(助言専用の教義)

## 絶対制約(違反する差分は理由を問わず差し戻し)
1. 助言専用: api/・taxii/ に書き込みSQLを入れない(tests/unit/test_api_static.py が監視)
2. 決定論: 重み合計1.0、reason[] 完全性、7要素決定論タプルのリプレイテストを壊さない
3. オフラインファースト: クエリパスに外部通信を追加しない
4. local.db 不可侵: バンドル/世代処理が研究データに触れる変更は禁止
5. フェイルクローズド: 部分的な reason[] を返す経路を作らない
6. コア依存は stdlib+PyYAML+idna+PyNaCl のみ

## ワークフロー
1. タスクを仕様化: 対象ファイル、受け入れ基準、テスト要件、制約を明記
2. Codex に実装させる(AGENTS.md が Codex 側の規範)
3. 敵対的レビュー: 制約1〜6、設計書との整合、テスト網羅、エッジケースを攻撃
4. 修正 → 再レビュー → python -m pytest tests/unit -q が全緑
5. ブランチにコミット、プッシュ、ドラフトPR作成(main 直接コミット禁止)

## 検証コマンド
- python -m pytest tests/unit -q      # 487+ passed が基準線
- python azctl check-config --config-dir config
```

### 3-2. `AGENTS.md`(Codex = 実装者の規範。Codex はこのファイルを自動で読む)

```markdown
# AGENTS.md — Azazel-CTI 実装規範

## プロジェクト
Raspberry Pi 4 上のオンプレ戦術CTIノード。設計は docs/design/phase1-implementation.md が
唯一の正。ADR(docs/adr/)は既決事項であり実装で覆さない。

## セットアップ / 検証
- source .venv/bin/activate
- pip install -e ".[api,dev]"
- python -m pytest tests/unit -q   # 全緑が完了条件(現在487本)

## 絶対制約(1つでも破ると差し戻し)
- api/・taxii/ 配下に INSERT/UPDATE/DELETE 等の書き込みSQLを書かない
- config/scoring.yaml の weights / confidence_weights は合計1.0(ローダが拒否する)
- scoring/correlate に wall-clock 直読み(datetime.now 等)を入れない — core/clock.py 経由
- local.db 側テーブル(reaction, observation, advisory_log 等)への破壊的変更禁止
- コアモジュールの依存は stdlib + PyYAML + idna + PyNaCl のみ。fastapi/pydantic は api/ 限定
- reaction 行は INSERT のみ(トリガが UPDATE/DELETE を拒否する)

## コード規約
- Python 3.11、型ヒント必須、ナレーション的コメント禁止(制約の明示のみ可)
- 新規コードには必ず tests/unit/ にテストを追加。既存テストの改変は指示がある場合のみ
- 1タスクで指示された所有ファイル以外に触れない

## 完了条件
python -m pytest tests/unit -q が全緑 + 指示された受け入れ基準を満たすこと。
完了報告には「作成/変更ファイル一覧」「テスト数」「判断に迷った点」を含めること。
```

---

## 4. タスク別開発指示(Claude Code に順番に渡す)

> 各指示はそのまま Claude Code へのプロンプトとして使える。Claude Code はこれを
> Codex 向け仕様に落とし、実装→敵対的レビュー→修正→再レビューまで回すこと。

### T1: GitHub Actions CI(最優先・小)

```
ブランチ ci/github-actions を切り、Codex に .github/workflows/test.yml を実装させよ。
要件: push/PR で ubuntu-latest + python3.11、pip install -e ".[api,dev]"、
python -m pytest tests/unit -q を実行。concurrency で同一refの多重実行をキャンセル。
所要3分以内に収まること。加えて azctl check-config --config-dir config を実行する
ジョブを含める。敵対的レビュー観点: キャッシュ毒性(actions/cache のキー設計)、
fork PR での secrets 非使用、pip の固定(ハッシュまでは不要、メジャー固定で可)。
完了後ドラフトPRを作成。
```

### T2: docs-sync-check.py 本実装(中)

```
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

```
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

```
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

```
Issue #12 の子Issue #1〜#11 それぞれについて、PR #15 の実装がどのファイル/テストで
受け入れ基準を満たしたかをコメントで対応表として記録し、満たしたものはクローズ提案
(クローズ自体はマスター承認後)。#14 も完遂済みなのでクローズ提案に含める。
未達部分(例: #10 の実機 provisioning 検証、#11 の実機手順検証)は新しい
「Pi 4 hardware validation」Issue に切り出して集約する。
```

### T6: S13 持ち越し検討(低優先・設計判断が必要なものは実装前にマスター確認)

```
以下は実装前に必ずマスターに選択肢を提示すること(勝手に実装しない):
- 共有メモリ GenCache(3×64MB 重複の解消)— multiprocessing.shared_memory 案の設計スパイク
- バンドル zstd 化 — zstandard 依存追加の是非(ADR 追記が必要)
- RLIMIT_AS vs cgroup ギャップの計測スクリプト
```

---

## 5. 敵対的レビューチェックリスト(Claude Code が毎PRで使う)

- [ ] 絶対制約1〜6に抵触する行が差分にないか(grep + 静的テスト)
- [ ] 新規コードに対応するテストがあるか。テストは実装の写経でなく仕様を検証しているか
- [ ] 決定論に影響する入力(wall-clock、乱数、環境変数、ファイル順序)が混入していないか
- [ ] エラーパスがフェイルクローズドか(例外を握りつぶして部分結果を返していないか)
- [ ] 設計書・ADR・docs との矛盾がないか。矛盾するなら文書改訂が同じPRにあるか
- [ ] `python -m pytest tests/unit -q` 全緑(487+)。テスト数が減っていないか
- [ ] 依存追加がないか(あるなら pyproject.toml と ADR 判断の明示)

---

## 6. 最初の1時間でやること(チェックリスト)

1. [ ] §1 の環境構築 → 487 テスト緑を確認
2. [ ] VS Code + Claude Code + Codex の認証確認(`codex login` 済みも確認)
3. [ ] Claude Code に §3 の CLAUDE.md / AGENTS.md を作成させ、最初のコミット(ブランチ chore/agent-guides)
4. [ ] まず **Option A(手動リレー)** で T1(CI)を1本通す — 体制の感触を掴む最小タスク
5. [ ] 慣れたら §2B の **Option B** を配線(`.claude/settings.json` 許可リスト + worktree 分離)
6. [ ] 以後 T2 → T3 → T4 の順に1タスク1PR(1worktree)で進める
```
