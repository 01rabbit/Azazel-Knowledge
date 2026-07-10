# Azazel-CTI 開発指示書 — MacBook 環境(Claude Code 指揮 × Codex 実装)

作成日: 2026-07-06 / 対象: `01rabbit/Azazel-CTI` main(PR #15 マージ後)

---

## 0. 現状分析

### main に入っているもの(Phase 1 + Phase 2 Behavioral CTI、現在 583テスト合格)

- 5巡の敵対的設計レビューを経た最終設計 `docs/design/phase1-implementation.md`(修正登録簿 F-1〜F-20 付き。以後「設計書」)
- Phase 1 実装一式: `src/azazel_cti/`(api / core / db / normalize / feeds / ingest / correlate / scoring / recommend / rules / patterns / reactions / attack / bundle / security / audit / taxii)、`worker.py`、`azctl`、`tools/`、`ops/`、`docs/operations.md`、`tests/unit`
- Phase 2 **Behavioral CTI**(issue #31〜#37、設計 `docs/design/phase2-implementation.md` の F2-1〜F2-20、[ADR-0009](adr/0009-behavioral-cti.md)): 行動パターン schema(`migrations/local/0002_behavior.sql`)、決定論生成器(`patterns/behavior_generate.py` + P2 + `azctl behavior`)、類似度/再現性(`scoring/behavior_similarity.py`)、friction timeline レポート(`reports/` + `reads.py`)、`/v1/context` の `behavioral_cti` ブロック、reaction ペイロード拡張(`0003_reaction_ext.sql`)、shadow scoring(`scoring/behavior_shadow.py`、default-off)
- テスト基準線の推移: Phase 1 = 487 → Phase 1 整備完了 = 518 → Phase 2 完了 = **583**(削除ゼロ)

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
| — | [Azazel-Common](https://github.com/01rabbit/Azazel-Common)(`azazel_common.cti_contracts`)の採用可否評価(要 pyproject.toml 変更 + 新規ADR + マスター判断。詳細は `docs/roadmap.md`) | ○(調査のみ) |

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
git clone https://github.com/01rabbit/Azazel-CTI.git
cd Azazel-CTI

# 3) Python 環境(venv 必須。システムPythonに直接入れない)
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[api,dev]"

# 4) 健全性確認(ここが緑になるまで先に進まない)
python -m pytest tests/unit -q          # 期待値: 583 passed(現行基準線)
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
- 現行基準線のテスト(583本)を1本でも壊した状態でのコミット禁止
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

1. [ ] §1 の環境構築 → 583 テスト緑を確認
2. [ ] VS Code + Claude Code + Codex の認証確認(`codex login` 済みも確認)
3. [ ] Claude Code に §3 の CLAUDE.md / AGENTS.md を作成させ、最初のコミット(ブランチ chore/agent-guides)
4. [ ] まず **Option A(手動リレー)** で T1(CI)を1本通す — 体制の感触を掴む最小タスク
5. [ ] 慣れたら §2B の **Option B** を配線(`.claude/settings.json` 許可リスト + worktree 分離)
6. [ ] 以後 T2 → T3 → T4 の順に1タスク1PR(1worktree)で進める
