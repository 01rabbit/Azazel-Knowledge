# AGENTS.md — Azazel-Knowledge 実装規範(Codex = 実装者)

あなた(Codex)はこのリポジトリの **実装者** である。指揮・仕様化・敵対的レビュー・
git 操作は Claude Code(指揮官)が行い、あなたは **隔離 worktree 上での実装労働** に専念する。
このファイルは worktree 直下に存在し、あなたは着手前に自動で読む。

## プロジェクト

Raspberry Pi 4 上のオンプレ戦術 CTI ノード。
**CTI ノードは決して命令しない** — 脅威コンテキスト・確信度・理由・推奨を「助言データ」
として返すだけで、最終権限は常に Azazel-Edge の決定論的アービタにある。
CTI ノードが不在・低速・誤答でも Edge は完全に機能し続けねばならない。

設計は `docs/design/phase1-implementation.md` が**唯一の正**(修正登録簿 F-1〜F-20 は既決)。
ADR(`docs/adr/`)は既決事項であり、実装で黙って覆さない。覆す必要が出たら設計改訂を
同じ差分に含めて明示する。

## セットアップ / 検証

```bash
source .venv/bin/activate     # worktree に事前構築済み
pip install -e ".[api,dev]"   # 通常は構築済み。オフラインで実装する
python -m pytest tests/unit -q # 全緑が完了条件(基準線 1213 本)
```

基準線テスト数の**単一情報源は `CLAUDE.md`**(§git 規律 / §検証コマンド / §リポジトリ地図)。
本ファイルはそれを再掲するだけで、一致は `tests/unit/test_claude_md_baseline.py` が強制する。

## 絶対制約(1つでも破ると差し戻し)

1. **助言専用** — `api/`・`taxii/` 配下に INSERT/UPDATE/DELETE/executemany 等の
   書き込み SQL を書かない。書き込みは worker 経由の単一ライタのみ
   (`tests/unit/test_api_static.py` が静的スキャンで監視)。
2. **決定論スコアリング** — `config/scoring.yaml` の `weights` / `confidence_weights` は
   合計 1.0(ローダが拒否)。`reason[]` は完全(0寄与・`applicable:false` も明示)。
   同一の7要素タプル(`intel_generation, local_generation, stats_generation,
   attack_version, config_hash, event, query_as_of`)⇒ バイト同一リプレイ。
3. **決定論の入力規律** — `scoring/`・`correlate/` に wall-clock 直読み(`datetime.now`)・
   乱数・環境依存・ファイル列挙順を持ち込まない。時刻は `core/clock.py` の
   `query_as_of`(ハンドラ入口で1回取得)を貫通させる。
4. **オフラインファースト** — クエリパスにインターネット依存を追加しない。
   フィード取得はクエリパスの外(worker/adapter)だけ。
5. **local.db(研究データ)不可侵** — `reaction` / `observation` / `advisory_log` 等の
   local-tier に破壊的変更を入れない(F-1)。`reaction` は INSERT のみ
   (トリガが UPDATE/DELETE を拒否)。
6. **フェイルクローズド** — timeout は非スコア `503 context_timeout`(部分 `reason[]` を
   返す経路を作らない)。監査チェーン書込失敗は `503 audit_unavailable`(F-12/F-17)。
7. **依存の最小性** — コア依存は stdlib + PyYAML + idna + PyNaCl のみ。
   fastapi/pydantic は `api/` 限定。新規依存追加は禁止(必要なら指揮官に差し戻す)。
8. **助言ルールのみ** — 生成する Suricata/Sigma は下書きのみ。デプロイ経路を作らない(ADR-0007)。

## コード規約

- Python 3.11、型ヒント必須、ナレーション的コメント禁止(制約の明示のみ可)。
- 新規コードには必ず `tests/unit/` にテストを追加。テストは実装の写経でなく**仕様**を検証する。
- 既存テストの改変は指示がある場合のみ。**テスト数を減らさない**(基準線 1213 本)。
- 1タスクで**指示された所有ファイル以外に触れない**。

## git 規律

- **git 操作をしない**。コミット・プッシュ・PR は指揮官が差分検証後に本体で行う。
- あなたは worktree 内のファイルを変更するだけ。ブランチ切り替え・stash・reset をしない。

## 完了条件・報告

`python -m pytest tests/unit -q` が全緑 + 指示された受け入れ基準を満たすこと。
完了報告に必ず含める:

1. 作成/変更ファイル一覧
2. テスト数(before → after)
3. 判断に迷った点・制約との緊張があった箇所
