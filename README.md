# Ubuntu Security Check

Ubuntuサーバーのログイン・公開ポート・SSH設定・アカウント・自動起動・更新状況を収集し、サーバー内にMarkdown / HTMLのレポートを保存するBashツールです。

**証跡収集用です。侵入なし・脆弱性なし・安全という合格判定は行いません。** 診断対象では設定変更、パッケージ導入、サービス停止、外部への結果送信を行いません。レポートと任意のZIPを新規作成します。`--sudo`はsudoの認証・監査記録を発生させる場合があります。

## Termiusから取得して実行

自分が管理するUbuntuサーバーに接続し、以下を実行します。GitHubから取得する段階では通信が必要です。診断本体はオフラインで動きます。

```bash
git clone https://github.com/tp-li-dev/ubuntu-security-check.git
cd ubuntu-security-check
git rev-parse HEAD
sha256sum -c SHA256SUMS
# 上の検証がすべてOKであることを確認してから実行
bash ubuntu-security-check.sh --sudo --zip
```

`git`がない場合は後述のcurl方式を利用できます。`--sudo`のパスワードはサーバー内で入力してください。通常ユーザーで実行し、必要な読み取りだけsudoを使います。認証失敗時は診断を開始しません。`sudo -n`による各取得で権限が失われた場合はERRORに記録します。

更新は前回と同じフォルダーで実行します。ローカル変更がある場合、勝手に上書きしません。

```bash
git pull --ff-only
git rev-parse HEAD
sha256sum -c SHA256SUMS
```

GitHub上のソースを確認してから実行してください。同じ配布元のチェックサムは、取得内容の整合性確認に使います。配布元そのものの侵害を検出する独立署名ではありません。

## git不要・コミットを固定して取得

GitHubの対象コミット画面で完全な40桁のコミットSHAをコピーします。`main`のような可変参照は補助スクリプトで拒否します。

```bash
# 以下の値を、確認した実際の40桁SHAに置き換える
REF='ここを完全な40桁のコミットSHAに置き換える'
curl --fail --show-error --location --proto '=https' --proto-redir '=https' \
  --connect-timeout 15 --max-time 120 \
  "https://raw.githubusercontent.com/tp-li-dev/ubuntu-security-check/$REF/run-from-github.sh" \
  --output run-from-github.sh
# 取得成功を確認し、必要に応じて内容を読む
less run-from-github.sh
bash run-from-github.sh --ref "$REF" -- --sudo --zip
```

補助スクリプトは本体とSHA256SUMSを同じコミットから取得し、本体の一致を検証してから実行します。ダウンロード失敗・チェックサム不一致時は実行しません。取得ファイルはカレントディレクトリの`ubuntu-security-check-source.*`に残すため、後から確認できます。取得だけ失敗した場合のファイルも残します。

## オプション

```bash
bash ubuntu-security-check.sh --help
bash ubuntu-security-check.sh --sudo --days 14 --timeout 60 --zip
bash ubuntu-security-check.sh --format md
bash ubuntu-security-check.sh --sudo --output ./reports/server-a-2026-10-16
```

| オプション | 動作 |
| --- | --- |
| `--sudo` | 認証後、保護された証跡をsudoで読み取る |
| `--days N` | SSH認証ログの期間。1〜365日、既定7日 |
| `--timeout N` | 1診断コマンドの時間制限。5〜300秒、既定30秒 |
| `--format md` | Markdownのみ。Python不要 |
| `--format both` | MarkdownとHTML。既定値、Python 3が必要 |
| `--output DIRECTORY` | 新規保存先を指定。既存パスへの上書きは拒否 |
| `--zip` | 保存先の隣にZIPを追加生成。元フォルダーも残す |

HTMLとZIPはPython 3の標準ライブラリを使うため、`zip`コマンドやpipパッケージは不要です。Python 3がなければ、診断開始前に案内して終了します。自動インストールはしません。最小構成では`--format md`を指定し、`--zip`を外してください。

Ubuntu 22.04 / 24.04をCI対象としています。Bash、coreutils、awk、sedを使います。`ufw`や`nft`などの診断用コマンドがない場合は、該当項目をSKIPPEDとして続行します。systemdの使えないコンテナではERRORになる項目があります。

## 出力と結果の回収

```text
reports/2026-10-16_063000Z-1234/
├── report.md
├── report.html
├── checks.tsv
├── SHA256SUMS
└── evidence/
    └── 01-system.txt ... 27-user-units.txt
reports/2026-10-16_063000Z-1234.zip  # --zip指定時のみ
```

保存先名とレポートの時刻はUTCです。ディレクトリは700、ファイル・ZIPは600の権限で新規作成します。親ディレクトリの既存権限は変更しません。管理者が書き込み可能な信頼できる保存先を使ってください。

TermiusのSFTP機能などでZIPまたはフォルダーを手元にダウンロードしてください。HTMLはダウンロード後、ブラウザで直接開けます。HTTPサーバーの起動やポート開放は不要です。HTMLは外部CSS・JavaScript・フォントを読み込まず、証跡をエスケープして表示します。

IP、アカウント名、ホスト情報などを含みます。ZIPは暗号化しません。パスワード・秘密鍵・環境変数・プロセス引数・cron設定の本文は意図的に収集しませんが、ログの自由文に機密情報が含まれる可能性はあります。共有前に確認してください。生の証跡は制御文字を含むことがあるため、閲覧には整形済みのレポートを推奨します。レポートを公開リポジトリにコミットしないでください。

## 状態と終了コード

| 状態 | 意味 |
| --- | --- |
| COLLECTED | コマンド終了コードが0。安全性を意味しない |
| SKIPPED | 権限またはコマンド不足で未取得 |
| ERROR | 診断コマンドが失敗。終了コードを併記 |
| TIMEOUT | 時間上限に到達。途中出力は残す |

終了コードは`0`＝全項目を取得、`1`＝レポートは生成したが未取得項目あり、`2`＝引数・前提条件・出力生成エラーです。`1`を「侵入検知」と解釈しないでください。ERRORやSKIPPEDを含むZIPも作成できます。出力処理が中断された場合は途中のファイルが残ることがあります。

## 診断の範囲

27項目を収集します。ログイン、SSH認証、実効SSHグローバル設定、TCP/UDP待ち受け、TCP接続、UFW/nftables/iptables、アカウント、プロセス名、systemd、cron等のファイルメタデータ、標準パスの公開鍵指紋、APT更新候補などです。

- SSH認証は指定期間の最新300件ずつ、wtmp/btmpは最新50件ずつ。ログ保持・ローテーション・設定によって見えない履歴があります。
- `sshd -T`は標準設定のグローバル値です。`Match`条件別の値、別設定ファイルで起動されたSSHサービスは網羅しません。
- 標準パス外の鍵、AuthorizedKeysCommand、全ユーザーのユーザーサービス、コンテナ内部、クラウド側FW、外部からの到達性は網羅しません。
- APTインデックスは更新せず、保存済みデータとその時刻を記録します。最新の修正提供状況の確認は別途必要です。
- 未知のプロセスやサービスの検出、脆弱性DBとの照合、パッケージ整合性の全面検証は行いません。
- root侵害後のサーバーではコマンド・ログ・レポート自体が信用できない場合があります。不審なログインや永続化が見つかった場合、このツールだけで侵入を否定しないでください。

## 開発時の検証

```bash
bash -n ubuntu-security-check.sh run-from-github.sh
shellcheck ubuntu-security-check.sh run-from-github.sh
sha256sum -c SHA256SUMS
python3 tests/test_diagnostic.py
```

テストは一時コピー内の診断コマンドを合成データに置き換えます。テスト実行先のSSH設定・認証ログ・鍵を収集しません。レポート生成、HTMLエスケープ、権限、ZIP、チェックサム、未取得・タイムアウト、上書き拒否、配布補助の実行拒否を検証します。実サーバーでの動作検証とは区別してください。

スクリプト変更後は`sha256sum ubuntu-security-check.sh run-from-github.sh > SHA256SUMS`を更新してください。
