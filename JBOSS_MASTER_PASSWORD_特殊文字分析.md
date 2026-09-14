# JBOSS_MASTER_PASSWORD 特殊文字影響分析

対象文字: `#` / `$` / `^` / `!` / 半角スペース / タブ / 改行 (`\n`) / `\` / `|`

- 分析日: 2026-09-15
- 検証環境: GNU bash 5.3.9(1)-release、dash（Git Bash on Windows 11）
- 本書の判定は推測ではなく、第 7 章の実測結果に基づく。

---

## 1. 結論サマリ

### 1.1 文字別の総合判定

| 文字 | 表記 | 総合判定 | 破綻する箇所 | 要約 |
|---|---|---|---|---|
| `#` | U+0023 シャープ | **問題なし** | — | シェルのコメント認識はトークナイズ時のみ。展開結果は再スキャンされないため、値の中の # は常にデータ。 |
| `$` | U+0024 ドル | **問題なし（注入境界のみ要注意）** | — | WildFly の式解決は解決結果を再走査しない。シェルも展開結果を再展開しない。ただし docker compose / K8s の値補間は別問題。 |
| `^` | U+005E ハット | **問題なし** | — | POSIX シェルのメタ文字ではない。ERE の ^ はパターン側の意味で、被検査文字列側には影響しない。 |
| `!` | U+0021 エクスクラメーション | **問題なし** | — | 履歴展開は対話シェル限定。非対話スクリプトでは set -H しても無効。 |
| `半角スペース` | U+0020 半角スペース | **問題あり** | S5 store_credentials.sh | read の行末トリムで末尾空白が消え、$* の単語分割で --secret 値が複数引数に割れる。 |
| `タブ` | U+0009 水平タブ | **致命的** | S8 JCEKS 層 / S5 store_credentials.sh | OpenJDK の SunJCE が PBE パスワードを印字可能 ASCII (0x20-0x7E) に限定するため、タブは資格情報ストアに格納できない（実測）。シェル側の $* 分割・read の行末トリムも重なる。 |
| `改行(\n)` | U+000A 改行 | **致命的** | S8 JCEKS 層 / S5 / S1 / S7 | JCEKS が改行を含むパスワードを拒否する（実測）ことに加え、printenv の行分割で値が切り詰められ、grep -v を素通りした後続行が正規表現に一致して資格情報ストアへ任意エイリアスを注入できる。 |
| `\` | U+005C バックスラッシュ | **問題あり** | S5 store_credentials.sh | read に -r が無いため \ がエスケープとして食われ、行末 \ は次行と連結して隣の秘密情報まで破壊する。 |
| `\|` | U+007C パイプ | **問題なし** | — | \| は演算子としてトークナイズ時にのみ認識される。展開結果は再トークナイズされないため常にデータ。 |

### 1.2 特殊文字とは独立に、先に直すべき重大事項

#### [最優先] JCEKS がタブ・改行・非 ASCII のパスワードを受け付けない（OpenJDK の仕様）

- **内容**: OpenJDK の SunJCE は JCEKS 秘密鍵エントリの PBE 保護パスワードを印字可能 ASCII (0x20-0x7E) に限定する。0x00-0xFF を走査し受理されたのは 95 文字のみであることを実測した。しかも空ストア作成は成功し、最初のエイリアス登録で初めて失敗するため、ビルドは通って起動で落ちる。
- **対処**: パスワードを 0x20-0x7E に限定し、起動前に範囲チェックを行って明示的に落とす。

#### [最優先] Dockerfile の --mount= 内のカンマ直後に空白がある

- **内容**: BuildKit の CSV パーサがキー名を認識できず build が失敗する。
- **対処**: --mount=type=secret,id=jboss_master_password,env=JBOSS_MASTER_PASSWORD,required=true（空白なし）。

#### [重大] LF を含むマスターパスワードによる資格情報ストアへのエイリアス注入

- **内容**: printenv | grep -v JBOSS_MASTER_PASSWORD は先頭行しか除去しない。2 行目以降がループへ流入し JBOSS_(.*_PASSWORD)=(.*) に一致すると任意のエイリアスを登録・上書きできる（実測で再現）。
- **対処**: printenv を廃止し compgen -e + 間接展開へ置換。加えて CR/LF を含む値を起動時に拒否する。

#### [重大] パスワードがコマンドライン引数に載る

- **内容**: elytron-tool.sh --password / add-user.sh の引数は ps -ef および /proc/<pid>/cmdline から同一 PID 名前空間の他プロセスに読まれる。
- **対処**: jboss-cli の add-alias(secret-value="${env.…}") 方式へ寄せ、argv からパスワードを排除する。

#### [重大] ビルド時と実行時でパスワードがバイト一致しないと起動不能

- **内容**: BuildKit の env= はシークレットファイルの生バイト列を渡すため、末尾 LF がそのまま値に含まれる。実行時に -e で渡した値と食い違い JCEKS が開けない。
- **対処**: シークレットは printf '%s' で末尾 LF なしに生成し、ビルド時にアサートする。

#### [中] 正規表現が未アンカーかつ貪欲

- **内容**: MY_JBOSS_ADMIN_PASSWORD のような無関係変数も一致し、値に _PASSWORD= を含むとキャプチャ位置がずれる（実測で再現）。
- **対処**: 変数名の列挙と完全一致判定に置き換える。

---

## 2. パスワードが通過する 8 つのステージ

どの文字がどこで壊れるかは、値が各ステージで「バイト列として渡るか」「テキストとして再パースされるか」で決まる。

### S1. BuildKit シークレット → 環境変数

```
Dockerfile: RUN --mount=type=secret,id=jboss_master_password,env=JBOSS_MASTER_PASSWORD,required=true
```

- **値の扱われ方**: シークレットファイルの生バイト列をそのまま環境変数に設定する。シェルによる解釈は一切介在しない。NUL のみ格納不可。
- **着眼点**: 末尾 LF が値に混入する典型的な落とし穴。

### S2. base.cli の式解決（WildFly ExpressionResolver）

```
/subsystem=elytron/credential-store=EAPCS:add(..., credential-reference={clear-text="${env.JBOSS_MASTER_PASSWORD}"}, create=true)
```

- **値の扱われ方**: パスワードの実値は .cli ファイル本文に一切出現しない。CLI は既定では式を解決せず（resolve-parameter-values 既定 false）、文字列 ${env.…} のまま管理層へ送られ、サーバ側が解決する。standalone.xml には式のまま永続化される。
- **着眼点**: 値がテキストとして CLI 構文・XML 構文を通らないため、本段は本質的に安全。

### S3. base-env.sh での再 export

```
export JBOSS_MASTER_PASSWORD=${JBOSS_MASTER_PASSWORD}（非クォート）
```

- **値の扱われ方**: export は宣言コマンド（declaration utility）であり、name=word 形式の引数は代入と同様に展開される。すなわち単語分割・パス名展開は行われない。bash 5.3 / bash --posix / dash のいずれでも実測確認済み。
- **着眼点**: 現状は偶然通っているだけ。仕様依存であり必ずクォートすべき。

### S4. create-admin-user.sh

```
${JBOSS_HOME}/bin/add-user.sh -sc ${JBOSS_HOME}/standalone/configuration "${JBOSS_ADMIN_USER}" "${JBOSS_ADMIN_PASSWORD}"
```

- **値の扱われ方**: パスワードはダブルクォート済みで単一の argv 要素として JVM へ渡る。管理レルムのパスワードは HEX(MD5(user:realm:pass)) にハッシュ化して mgmt-users.properties へ保存されるため、値そのものが properties 構文を通ることはない。
- **着眼点**: -sc の引数が非クォートである点のみ別途要修正。

### S5. store_credentials.sh

```
printenv | grep -v JBOSS_MASTER_PASSWORD | while read line → [[ =~ ]] → jboss_credential_store の $*
```

- **値の扱われ方**: 本パイプライン中で唯一、パスワードを「テキスト行」として再パースする段。行指向読み取り・エスケープ解釈・IFS 分割・グロブ展開の 4 つが重なる。
- **着眼点**: 特殊文字事故のほぼ全てがここに集中する。

### S6. ランチャスクリプト（elytron-tool.sh / add-user.sh）

```
eval \"$JAVA\" $JAVA_OPTS -jar ... '"$@"'
```

- **値の扱われ方**: eval が再パースするのはテキスト "$@" であり、$@ の展開結果は再展開されない。したがって値中の $ ` \ " は再解釈されない。
- **着眼点**: この eval は安全側の定石。ただし $JAVA_OPTS 非クォートは別のリスク。

### S7. 実行時 standalone.sh

```
exec ${JBOSS_HOME}/bin/standalone.sh -b 0.0.0.0 -bmanagement 0.0.0.0 -c standalone.xml
```

- **値の扱われ方**: standalone.xml 内の ${env.JBOSS_MASTER_PASSWORD} をサーバ JVM の環境変数から解決し、JCEKS を開く。ビルド時／初回作成時に使われた値とバイト単位で一致する必要がある。
- **着眼点**: 実行時コンテナにも同じ環境変数が必須。

### S8. 資格情報ストア実体（JCEKS + SunJCE PBE）

```
secrets.jceks への SecretKeyEntry 格納（base.cli の create=true 後の add-alias、elytron-tool.sh --add、実行時の資格情報登録）
```

- **値の扱われ方**: Elytron の KeyStoreCredentialStore は各資格情報を JCEKS の SecretKeyEntry として格納し、ストアパスワードで PBE 保護する。SunJCE の鍵導出がパスワードを印字可能 ASCII (0x20-0x7E) に限定するため、範囲外の文字は InvalidKeySpecException で拒否される。
- **着眼点**: シェルの修正では回避できない、本環境における最終的な関門。空ストア作成（MAC のみ）は通るため、失敗は最初のエイリアス登録まで遅延する。

---

## 3. 文字 × ステージ 判定マトリクス

凡例: `OK` = 値が一切変化しない / `△` = 条件次第で破綻、または運用経路で事故る / `NG` = 値が破壊される、処理が失敗する

| 文字 | S1 | S2 | S3 | S4 | S5 | S6 | S7 | S8 | 総合 |
|---|---|---|---|---|---|---|---|---|---|
| `#` | OK | OK | OK | OK | OK | OK | △ | OK | **問題なし** |
| `$` | OK | OK | OK | OK | OK | OK | △ | OK | **問題なし（注入境界のみ要注意）** |
| `^` | OK | OK | OK | OK | OK | OK | OK | OK | **問題なし** |
| `!` | OK | OK | OK | OK | OK | OK | OK | OK | **問題なし** |
| `半角スペース` | OK | OK | OK | OK | NG | OK | OK | OK | **問題あり** |
| `タブ` | OK | △ | OK | OK | NG | OK | △ | NG | **致命的** |
| `改行(\n)` | △ | △ | OK | OK | NG | OK | NG | NG | **致命的** |
| `\` | OK | OK | OK | OK | NG | OK | OK | OK | **問題あり** |
| `\|` | OK | OK | OK | OK | OK | OK | OK | OK | **問題なし** |

- **S1** = BuildKit シークレット → 環境変数
- **S2** = base.cli の式解決（WildFly ExpressionResolver）
- **S3** = base-env.sh での再 export
- **S4** = create-admin-user.sh
- **S5** = store_credentials.sh
- **S6** = ランチャスクリプト（elytron-tool.sh / add-user.sh）
- **S7** = 実行時 standalone.sh
- **S8** = 資格情報ストア実体（JCEKS + SunJCE PBE）

---

## 4. 文字別 詳細分析

### 4.1 `#` （U+0023 シャープ） ― 総合判定: **問題なし**

> シェルのコメント認識はトークナイズ時のみ。展開結果は再スキャンされないため、値の中の # は常にデータ。

#### S1 BuildKit シークレット → 環境変数 ― `OK`

- **現象**: 値はバイト列としてそのまま環境変数に入る。
- **技術的根拠**: BuildKit の env= はシークレットの内容をシェルを介さず直接 environ に設定するため、# が特別扱いされる経路が存在しない。
- **対処**: 不要。

#### S2 base.cli の式解決（WildFly ExpressionResolver） ― `OK`

- **現象**: 値が .cli ファイル本文に現れないため CLI のコメント構文に触れない。
- **技術的根拠**: jboss-cli は行頭 # をコメントとして扱うが、base.cli に書かれているのは ${env.JBOSS_MASTER_PASSWORD} という式のみ。実値はサーバ側の式解決で注入されるため、CLI の字句解析を一度も通らない。XML・JCEKS でも # は非特殊。
- **対処**: 不要。

#### S3 base-env.sh での再 export ― `OK`

- **現象**: export VAR=${VAR} の展開結果に含まれる # はコメント開始にならない。
- **技術的根拠**: シェルにおけるコメント認識はトークナイズ（字句解析）の段階で行われ、パラメータ展開はその後に実行される。展開結果が再度トークナイズされることはない。実測: 値 '#leading' が単一引数として保持されることを確認。
- **対処**: 不要。

#### S4 create-admin-user.sh ― `OK`

- **現象**: ダブルクォート内のため確実に単一引数。
- **技術的根拠**: 同上。add-user は値を MD5 ハッシュ化して保存するため、properties ファイルのコメント構文にも触れない。
- **対処**: 不要。

#### S5 store_credentials.sh ― `OK`

- **現象**: read・正規表現・$* のいずれでも # は変化しない。
- **技術的根拠**: read は # を特別扱いしない。ERE において # はメタ文字ではない。$* の単語分割は IFS（既定で空白・タブ・改行）に基づくため # では分割されない。分割後の語が再トークナイズされることもないため、# はコメントにならない。実測で確認。
- **対処**: 不要。

#### S6 ランチャスクリプト（elytron-tool.sh / add-user.sh） ― `OK`

- **現象**: eval の再パース対象はテキスト "$@" のみ。
- **技術的根拠**: $@ の展開結果は再展開・再トークナイズされない。
- **対処**: 不要。

#### S7 実行時 standalone.sh ― `△`

- **現象**: 本コードでは問題ないが、値の受け渡し方法によっては欠落しうる。
- **技術的根拠**: docker run --env-file および多くの .env パーサは行頭の # をコメントとして破棄する。行中の # は値の一部として保持される実装が一般的だが、実装差がある。
- **対処**: --env-file を使わず -e / Docker secret / Kubernetes Secret を用いる。やむを得ず env-file を使う場合は先頭文字に # を置かない。

#### S8 資格情報ストア実体（JCEKS + SunJCE PBE） ― `OK`

- **現象**: 印字可能 ASCII の範囲内 (0x20-0x7E) にあるため、SunJCE の PBE 鍵導出をそのまま通過する。（0x23）
- **技術的根拠**: 0x00-0xFF の全 256 文字を JCEKS の SecretKeyEntry 格納で走査したところ、受理されたのは 0x20-0x7E の 95 文字のみであった（OpenJDK 17.0.11 で実測。当該チェックは com.sun.crypto.provider.PBEKey にあり OpenJDK 21 でも同一）。
- **対処**: 不要。

### 4.2 `$` （U+0024 ドル） ― 総合判定: **問題なし（注入境界のみ要注意）**

> WildFly の式解決は解決結果を再走査しない。シェルも展開結果を再展開しない。ただし docker compose / K8s の値補間は別問題。

#### S1 BuildKit シークレット → 環境変数 ― `OK`

- **現象**: バイト列としてそのまま環境変数へ。
- **技術的根拠**: シェル解釈が介在しない。
- **対処**: 不要。

#### S2 base.cli の式解決（WildFly ExpressionResolver） ― `OK`

- **現象**: WildFly の式解決は解決結果を再走査しないため、値中の $ や ${ が再解釈されることはない。
- **技術的根拠**: org.jboss.dmr.ValueExpression#resolveString は式文字列を左から走査し、${ を検出すると対応する } までを名前として解決し、解決結果を出力バッファへ追記したうえで走査位置を元文字列の } の直後へ進める。追記された解決結果が再びスキャンされることはない（非再帰）。したがって値が 'a${b}c' や 'a$$b' であっても、そのまま資格情報ストアのパスワードとして使われる。なお $$ は式リテラル側のエスケープ（→ $ 一文字）であり、base.cli 本文には $$ を書いていないため無関係。
- **対処**: 不要。ただし base.cli に実値を直書きする運用へ変えないこと。

#### S3 base-env.sh での再 export ― `OK`

- **現象**: 展開結果は再展開されない。
- **技術的根拠**: POSIX シェルの展開は一度きりで、結果に対する再帰的なパラメータ展開は行われない。実測で確認。
- **対処**: 不要。

#### S4 create-admin-user.sh ― `OK`

- **現象**: ダブルクォート内で単一引数として渡る。
- **技術的根拠**: 同上。
- **対処**: 不要。

#### S5 store_credentials.sh ― `OK`

- **現象**: read・[[ =~ ]]・$* のいずれでも $ は復活しない。
- **技術的根拠**: read は入力を再展開しない。[[ ${line} =~ ... ]] の左辺は展開済み文字列であり、正規表現側の意味も持たない。$* の単語分割・パス名展開は行われるが、パラメータ展開の再実行は含まれない。実測: 値 'p$q' が BASH_REMATCH[2] に正しく格納されることを確認。
- **対処**: 不要。

#### S6 ランチャスクリプト（elytron-tool.sh / add-user.sh） ― `OK`

- **現象**: eval を通っても値は再展開されない。
- **技術的根拠**: eval \"$JAVA\" ... '"$@"' という定型では、eval が受け取る文字列中の "$@" が eval のパース時に展開され、各位置パラメータが個別の語になる。展開結果は再展開されないため、値中の $ ` \ " は保持される。これが add-user.sh / elytron-tool.sh で採用されている定石。
- **対処**: 不要。

#### S7 実行時 standalone.sh ― `△`

- **現象**: 本コードでは問題ないが、環境変数を設定する側（コード外）で最も事故が多い文字。
- **技術的根拠**: docker compose の YAML は environment 値に対して変数補間を行うため $ は $$ にエスケープしなければ消える。compose の .env も同様。Kubernetes の env[].value は $(VAR) 形式を展開するため $$( でのエスケープが必要。CI の秘密変数 UI でも展開されうる。
- **対処**: 値の受け渡しは Docker BuildKit secret / Kubernetes Secret の secretKeyRef / ファイルマウントに限定し、文字列補間される経路（compose の直書き、--env-file）を避ける。

#### S8 資格情報ストア実体（JCEKS + SunJCE PBE） ― `OK`

- **現象**: 印字可能 ASCII の範囲内 (0x20-0x7E) にあるため、SunJCE の PBE 鍵導出をそのまま通過する。（0x24）
- **技術的根拠**: 0x00-0xFF の全 256 文字を JCEKS の SecretKeyEntry 格納で走査したところ、受理されたのは 0x20-0x7E の 95 文字のみであった（OpenJDK 17.0.11 で実測。当該チェックは com.sun.crypto.provider.PBEKey にあり OpenJDK 21 でも同一）。
- **対処**: 不要。

### 4.3 `^` （U+005E ハット） ― 総合判定: **問題なし**

> POSIX シェルのメタ文字ではない。ERE の ^ はパターン側の意味で、被検査文字列側には影響しない。

#### S1 BuildKit シークレット → 環境変数 ― `OK`

- **現象**: バイト列としてそのまま。
- **技術的根拠**: シェル解釈なし。
- **対処**: 不要。

#### S2 base.cli の式解決（WildFly ExpressionResolver） ― `OK`

- **現象**: 値が CLI 本文に現れず、WildFly 式構文・XML・JCEKS のいずれでも ^ は非特殊。
- **技術的根拠**: 式構文で意味を持つのは ${ } : $$ のみ。
- **対処**: 不要。

#### S3 base-env.sh での再 export ― `OK`

- **現象**: ^ は POSIX シェルのメタ文字ではない。
- **技術的根拠**: 現行の sh/bash における ^ に特別な意味はない（初期 Bourne shell で | の別名だった歴史はあるが現行実装では非該当）。bash の ${var^} / ${var^^} は変数名側に付く大文字化構文であり、値の中の ^ とは無関係。
- **対処**: 不要。

#### S4 create-admin-user.sh ― `OK`

- **現象**: 変化なし。
- **技術的根拠**: 同上。
- **対処**: 不要。

#### S5 store_credentials.sh ― `OK`

- **現象**: 正規表現の被検査文字列側にあるため、アンカーとしての意味を持たない。
- **技術的根拠**: [[ ${line} =~ JBOSS_(.*_PASSWORD)=(.*) ]] において ^ がアンカーとして機能するのは右辺（パターン）に書かれた場合のみ。左辺は単なる被検査文字列である。実測: 値 'p^q' が正しくキャプチャされることを確認。IFS にも含まれないため $* でも分割されない。
- **対処**: 不要。

#### S6 ランチャスクリプト（elytron-tool.sh / add-user.sh） ― `OK`

- **現象**: 変化なし。
- **技術的根拠**: 同上。
- **対処**: 不要。

#### S7 実行時 standalone.sh ― `OK`

- **現象**: 変化なし。
- **技術的根拠**: ただしコード外の注意として、Windows の cmd.exe はエスケープ文字が ^ であるため set JBOSS_MASTER_PASSWORD=a^b は 'ab' になる。PowerShell のエスケープはバッククォートであり ^ は影響しない。
- **対処**: Windows から手動設定する場合のみ ^^ とするか PowerShell / WSL を用いる。

#### S8 資格情報ストア実体（JCEKS + SunJCE PBE） ― `OK`

- **現象**: 印字可能 ASCII の範囲内 (0x20-0x7E) にあるため、SunJCE の PBE 鍵導出をそのまま通過する。（0x5E）
- **技術的根拠**: 0x00-0xFF の全 256 文字を JCEKS の SecretKeyEntry 格納で走査したところ、受理されたのは 0x20-0x7E の 95 文字のみであった（OpenJDK 17.0.11 で実測。当該チェックは com.sun.crypto.provider.PBEKey にあり OpenJDK 21 でも同一）。
- **対処**: 不要。

### 4.4 `!` （U+0021 エクスクラメーション） ― 総合判定: **問題なし**

> 履歴展開は対話シェル限定。非対話スクリプトでは set -H しても無効。

#### S1 BuildKit シークレット → 環境変数 ― `OK`

- **現象**: バイト列としてそのまま。
- **技術的根拠**: シェル解釈なし。
- **対処**: 不要。

#### S2 base.cli の式解決（WildFly ExpressionResolver） ― `OK`

- **現象**: 非特殊。
- **技術的根拠**: 式構文・XML・JCEKS いずれでも ! に意味はない。
- **対処**: 不要。

#### S3 base-env.sh での再 export ― `OK`

- **現象**: 履歴展開は非対話シェルでは無効。
- **技術的根拠**: bash の履歴展開（histexpand, set -H）は対話シェルでのみ既定で有効。スクリプト実行such as bash script.sh は非対話であり、明示的に set -H しても履歴機構自体が無効なため展開は発生しない。実測で確認。さらに履歴展開は入力テキストに対する前処理であり、パラメータ展開の結果には適用されない。
- **対処**: 不要。

#### S4 create-admin-user.sh ― `OK`

- **現象**: 変化なし。
- **技術的根拠**: 同上。
- **対処**: 不要。

#### S5 store_credentials.sh ― `OK`

- **現象**: read・正規表現・$* のいずれでも非特殊。
- **技術的根拠**: ERE において ! はメタ文字ではない。[[ ! expr ]] の否定演算子は独立した語としての ! のみが該当し、文字列中の ! とは無関係。実測で確認。
- **対処**: 不要。

#### S6 ランチャスクリプト（elytron-tool.sh / add-user.sh） ― `OK`

- **現象**: 変化なし。
- **技術的根拠**: 同上。
- **対処**: 不要。

#### S7 実行時 standalone.sh ― `OK`

- **現象**: 変化なし。
- **技術的根拠**: コード外の注意として、対話 bash で export JBOSS_MASTER_PASSWORD="a!b" と手打ちすると履歴展開が働き失敗またはコマンド化けを起こす。シングルクォートなら安全。
- **対処**: 手動設定時はシングルクォートを使う。

#### S8 資格情報ストア実体（JCEKS + SunJCE PBE） ― `OK`

- **現象**: 印字可能 ASCII の範囲内 (0x20-0x7E) にあるため、SunJCE の PBE 鍵導出をそのまま通過する。（0x21）
- **技術的根拠**: 0x00-0xFF の全 256 文字を JCEKS の SecretKeyEntry 格納で走査したところ、受理されたのは 0x20-0x7E の 95 文字のみであった（OpenJDK 17.0.11 で実測。当該チェックは com.sun.crypto.provider.PBEKey にあり OpenJDK 21 でも同一）。
- **対処**: 不要。

### 4.5 `半角スペース` （U+0020 半角スペース） ― 総合判定: **問題あり**

> read の行末トリムで末尾空白が消え、$* の単語分割で --secret 値が複数引数に割れる。

#### S1 BuildKit シークレット → 環境変数 ― `OK`

- **現象**: 値はバイト列としてそのまま環境変数へ入る。
- **技術的根拠**: BuildKit はシェルを介さず environ を設定するため、空白の有無はそのまま保持される。
- **対処**: 不要。

#### S2 base.cli の式解決（WildFly ExpressionResolver） ― `OK`

- **現象**: 式のまま XML へ永続化されるため、XML の属性値正規化の影響を受けない。
- **技術的根拠**: WildFly は clear-text が式許可属性であることから ${env.JBOSS_MASTER_PASSWORD} を ValueExpression として保持し、standalone.xml には式文字列のまま書き出す。解決はメモリ上で行われるため空白はそのまま JCEKS のパスワードとして使われる。式解決に trim 処理は存在しない。
- **対処**: 不要。ただし clear-text に実値を直書きする運用にすると XML 属性値正規化の影響を受けるため禁止。

#### S3 base-env.sh での再 export ― `OK`

- **現象**: 宣言コマンド規則により単語分割が発生しない。
- **技術的根拠**: export は declaration utility であり、name=word 形式の引数はチルダ展開・パラメータ展開・コマンド置換・算術展開・クォート除去のみを受け、単語分割とパス名展開は行われない。実測: bash 5.3 / bash --posix / dash のいずれでも 'a b  c' がそのまま保持されることを確認。
- **対処**: 仕様依存であり脆い。export JBOSS_MASTER_PASSWORD="${JBOSS_MASTER_PASSWORD:?}" と明示クォートすること。

#### S4 create-admin-user.sh ― `OK`

- **現象**: ダブルクォート済みで単一 argv として渡る。
- **技術的根拠**: add-user はパスワードをハッシュ化して保存するため、空白が properties 構文に触れることもない。
- **対処**: 不要。

#### S5 store_credentials.sh ― `NG`

- **現象**: (a) read の行末トリムで値末尾の空白が消える。(b) $* の単語分割で --secret の値が複数引数へ割れる。
- **技術的根拠**: (a) read に IFS= 指定が無い場合、行の先頭および末尾の IFS 空白類が field splitting により除去される。printenv の出力は JBOSS_X_PASSWORD=<値> 形式なので値の先頭空白は行の途中に位置し保持されるが、値の末尾空白は行末にあたるため削除される。実測: 末尾 2 空白が消えることを確認。 (b) 関数内の $* は非クォートのため IFS で単語分割される。実測: --secret に 'my pass word' を渡すと --secret / my / pass / word の 4 語に分解され、elytron-tool は my を秘密値とみなし残りを不正な引数として扱う。 なおマスターパスワード自体は --password "${JBOSS_MASTER_PASSWORD}" とクォートされ、かつ grep -v によりループを通らないため、この 2 点の直接被害は受けない。被害を受けるのは JBOSS_ADMIN_PASSWORD 等ループ経由の秘密情報である。
- **対処**: while IFS= read -r を用いる。関数の $* を "$@" に変更する。さらに printenv 依存をやめ compgen -e と間接展開 ${!name} に置換すれば、値がテキスト行を経由しなくなり本問題は根本的に消える。

#### S6 ランチャスクリプト（elytron-tool.sh / add-user.sh） ― `OK`

- **現象**: argv に空白を含めても eval では分割されない。
- **技術的根拠**: "$@" 展開の結果は再トークナイズされない。
- **対処**: 不要。

#### S7 実行時 standalone.sh ― `OK`

- **現象**: 環境変数値としての空白は保持される。
- **技術的根拠**: ただし --env-file や CI の変数入力欄では前後の空白がトリムされる実装があり、ビルド時と実行時で値が食い違う恐れがある。
- **対処**: 先頭・末尾の空白はポリシーで禁止するのが安全。

#### S8 資格情報ストア実体（JCEKS + SunJCE PBE） ― `OK`

- **現象**: 印字可能 ASCII の範囲内 (0x20-0x7E) にあるため、SunJCE の PBE 鍵導出をそのまま通過する。（0x20）
- **技術的根拠**: 0x00-0xFF の全 256 文字を JCEKS の SecretKeyEntry 格納で走査したところ、受理されたのは 0x20-0x7E の 95 文字のみであった（OpenJDK 17.0.11 で実測。当該チェックは com.sun.crypto.provider.PBEKey にあり OpenJDK 21 でも同一）。
- **対処**: 不要。

### 4.6 `タブ` （U+0009 水平タブ） ― 総合判定: **致命的**

> OpenJDK の SunJCE が PBE パスワードを印字可能 ASCII (0x20-0x7E) に限定するため、タブは資格情報ストアに格納できない（実測）。シェル側の $* 分割・read の行末トリムも重なる。

#### S1 BuildKit シークレット → 環境変数 ― `OK`

- **現象**: バイト列としてそのまま。
- **技術的根拠**: S1 はシェル解釈を介さない。
- **対処**: 不要。

#### S2 base.cli の式解決（WildFly ExpressionResolver） ― `△`

- **現象**: 式のままであれば無害だが、実値を XML 属性に書くと空白へ変換される。
- **技術的根拠**: XML 1.0 の属性値正規化（3.3.3 節）では、リテラルの TAB(#x9)・LF(#xA)・CR(#xD) は空白(#x20)に置換される。本コードは式を永続化するためこの経路には入らないが、--resolve-parameter-values の使用や clear-text への実値直書きを行うと、再読込時にタブが空白化してパスワードが変わる。
- **対処**: 式 ${env....} 方式を維持する。CLI で --resolve-parameter-values を使わない。

#### S3 base-env.sh での再 export ― `OK`

- **現象**: 宣言コマンド規則により分割されない。
- **技術的根拠**: 実測でタブを含む値が export 後も保持されることを確認。
- **対処**: 明示クォートを推奨。

#### S4 create-admin-user.sh ― `OK`

- **現象**: 単一 argv として渡る。
- **技術的根拠**: S4 はダブルクォート済み。
- **対処**: 不要。

#### S5 store_credentials.sh ― `NG`

- **現象**: 空白と同一の IFS 要因により、行末タブの消失と $* の単語分割が発生する。
- **技術的根拠**: 既定 IFS は space・tab・newline であり、タブは空白と全く同じ扱いを受ける。実測: 値末尾のタブが read により失われることを od -c で確認。$* でもタブ位置で分割される。加えてタブは画面上不可視であるため、値が壊れても検知が極めて困難という運用上の悪性がある。
- **対処**: 空白と同じ修正（IFS= read -r / "$@" / compgen -e 方式）。加えてポリシーでタブを禁止することを強く推奨。

#### S6 ランチャスクリプト（elytron-tool.sh / add-user.sh） ― `OK`

- **現象**: argv 中のタブは保持される。
- **技術的根拠**: "$@" は再トークナイズされない。
- **対処**: 不要。

#### S7 実行時 standalone.sh ― `△`

- **現象**: 受け渡し経路でタブが失われやすい。
- **技術的根拠**: .env ファイル、Kubernetes マニフェストの YAML、CI の変数入力欄などでタブは空白へ変換されたり削除されたりする実装が多く、ビルド時と実行時の不一致を招く。
- **対処**: タブは使用しない。

#### S8 資格情報ストア実体（JCEKS + SunJCE PBE） ― `NG`

- **現象**: JCEKS の秘密鍵エントリ格納が InvalidKeySpecException: Password is not ASCII で失敗する。
- **技術的根拠**: タブは 0x09 であり、SunJCE の PBEWithMD5AndTripleDES 鍵導出が要求する印字可能 ASCII (0x20-0x7E) の範囲外。setEntry(SecretKeyEntry) の時点で例外となることを実測で切り分けた。一方、秘密鍵エントリを含まない空ストアの store()/load() はタブでも成功するため、base.cli の create=true によるストア作成自体はビルド時に通ってしまう。失敗は最初の add-alias まで遅延し、原因表示も Password is not ASCII とだけ出るため、タブが原因だと気づきにくい。
- **対処**: シェル側の修正では回避不能。タブを禁止する以外に対処はない。起動前に 0x20-0x7E の範囲チェックを入れ、明示的なエラーメッセージで落とすこと。

### 4.7 `改行(\n)` （U+000A 改行） ― 総合判定: **致命的**

> JCEKS が改行を含むパスワードを拒否する（実測）ことに加え、printenv の行分割で値が切り詰められ、grep -v を素通りした後続行が正規表現に一致して資格情報ストアへ任意エイリアスを注入できる。

#### S1 BuildKit シークレット → 環境変数 ― `△`

- **現象**: シークレットファイル末尾の LF がそのまま値に混入する。
- **技術的根拠**: BuildKit の --mount=type=secret,env=NAME はシークレットの内容をバイト列としてそのまま環境変数へ設定する。echo 'pw' > secret.txt のように生成すると値は pw+LF となる。ビルド時にはこの値で JCEKS が作成されるが、実行時に -e JBOSS_MASTER_PASSWORD=pw を渡すと一致せず、起動時に資格情報ストアを開けない。環境変数自体は LF を格納できる（格納できないのは NUL のみ）ため、エラーにならず静かに不一致となる点が悪質。
- **対処**: シークレットは printf '%s' で末尾 LF なしに生成する。さらにビルド時に LF を含む値を検出して失敗させるアサートを入れる。

#### S2 base.cli の式解決（WildFly ExpressionResolver） ― `△`

- **現象**: 式のままなら保持されるが、実値を XML 属性へ書くと空白に潰れる。
- **技術的根拠**: XML 属性値正規化により LF は空白へ変換される。本コードは式を永続化するため直接の被害はなく、資格情報ストアの作成も式解決後のメモリ上の値で行われるため LF はそのまま JCEKS のパスワードになる。しかし同じ値を system-property 等 XML 経由で永続化する箇所へ書くと空白化し、値が分岐して追跡困難な不整合を生む。
- **対処**: LF を含むパスワードを許可しない。

#### S3 base-env.sh での再 export ― `OK`

- **現象**: 宣言コマンド規則により LF は保持される。
- **技術的根拠**: 実測: 改行を含む値が export 後も同一バイト列として保持されることを od -c で確認。
- **対処**: 明示クォートを推奨。

#### S4 create-admin-user.sh ― `OK`

- **現象**: argv に LF を含めることは可能で、そのまま JVM へ渡る。
- **技術的根拠**: execve の引数は NUL 区切りであり、LF は通常のバイトとして扱われる。
- **対処**: 不要。

#### S5 store_credentials.sh ― `NG`

- **現象**: 値の切り詰め・grep -v の素通り・資格情報ストアへのエイリアス注入という多段階の破綻が起きる。本分析における最悪の欠陥。
- **技術的根拠**: (1) printenv の出力は行指向であり、LF を含む値は複数行に分裂する。 (2) grep -v JBOSS_MASTER_PASSWORD は JBOSS_MASTER_PASSWORD= を含む先頭行しか除去しない。値の 2 行目以降はそのままループへ流入する（マスターパスワード断片のログ露出リスク）。 (3) while read line は 1 行分しか読まないため、ループで処理される秘密情報は最初の LF で切り詰められる。 (4) 最も重大な点として、流入した後続行が JBOSS_(.*_PASSWORD)=(.*) に一致すると、任意のエイリアスを資格情報ストアへ登録・上書きできる。実測: JBOSS_MASTER_PASSWORD に Mast + LF + PART2 + LF + JBOSS_FAKE_PASSWORD=injected を設定したところ、alias=fake-password / secret=injected が追加対象として検出された。マスターパスワードの生成元が信頼できない場合、これは資格情報ストアへの注入経路となる。 (5) $* の IFS には LF が含まれるため、ここでも分割が起きる。
- **対処**: printenv を廃し compgen -e（環境変数名の列挙。名前に LF は含まれ得ない）と間接展開 ${!name} を用いる。加えて CR/LF を含む秘密情報を検出したら即座に fail させるガードを入れる。

#### S6 ランチャスクリプト（elytron-tool.sh / add-user.sh） ― `OK`

- **現象**: argv 中の LF は保持される。
- **技術的根拠**: "$@" は再トークナイズされない。
- **対処**: 不要。

#### S7 実行時 standalone.sh ― `NG`

- **現象**: ビルド時と実行時で同一バイト列を渡し続けることが現実的に困難。
- **技術的根拠**: docker run --env-file は 1 行 1 変数の形式であり LF を表現できない。docker compose の environment も同様。Kubernetes Secret の stringData なら表現可能だが、運用者が値を目視確認・再入力する過程で高確率で壊れる。ps 出力やログも壊れ、障害解析を著しく困難にする。
- **対処**: LF・CR は例外なく禁止する。

#### S8 資格情報ストア実体（JCEKS + SunJCE PBE） ― `NG`

- **現象**: JCEKS の秘密鍵エントリ格納が InvalidKeySpecException: Password is not ASCII で失敗する。
- **技術的根拠**: 改行は 0x0A であり印字可能 ASCII の範囲外。復帰 (0x0D) も同様に拒否される。タブと同じく空ストア作成は通り、最初のエイリアス登録で失敗する。シークレットファイル末尾の LF がそのまま環境変数に入る構成（EV-05）では、運用者が意図せずこの状態に陥る。
- **対処**: シェル側の修正では回避不能。改行・復帰を禁止し、シークレット生成を printf '%s' に統一したうえで末尾 LF 除去と範囲チェックを行う。

### 4.8 `\` （U+005C バックスラッシュ） ― 総合判定: **問題あり**

> read に -r が無いため \ がエスケープとして食われ、行末 \ は次行と連結して隣の秘密情報まで破壊する。

#### S1 BuildKit シークレット → 環境変数 ― `OK`

- **現象**: バイト列としてそのまま。
- **技術的根拠**: S1 はシェル解釈を介さない。
- **対処**: 不要。

#### S2 base.cli の式解決（WildFly ExpressionResolver） ― `OK`

- **現象**: WildFly の式構文にバックスラッシュエスケープは存在しない。
- **技術的根拠**: 式解決で意味を持つのは ${ } と : と $$ のみであり、バックスラッシュはそのまま値の一部として扱われる。XML 属性値でも非特殊。JCEKS のパスワードは char[] として扱われるため通常の文字。
- **対処**: 不要。ただし .cli 本文に実値を直書きする場合、jboss-cli のコマンド構文ではバックスラッシュがエスケープ文字となるため注意。

#### S3 base-env.sh での再 export ― `OK`

- **現象**: 展開結果が再エスケープ解釈されることはない。
- **技術的根拠**: パラメータ展開の結果に対してクォート除去やエスケープ処理が再適用されることはない。
- **対処**: 明示クォートを推奨。

#### S4 create-admin-user.sh ― `OK`

- **現象**: ダブルクォート内で単一 argv として渡る。
- **技術的根拠**: add-user はパスワードをハッシュ化して保存するため、properties ファイルのバックスラッシュエスケープ規則に値が触れることはない（ユーザ名側は影響を受けるが本件の対象外）。
- **対処**: 不要。

#### S5 store_credentials.sh ― `NG`

- **現象**: read に -r が無いためバックスラッシュがエスケープとして消費される。
- **技術的根拠**: (1) read は -r を付けない場合、バックスラッシュを次の文字のエスケープとして解釈し、バックスラッシュ自体を除去する。実測: JBOSS_ADMIN_PASSWORD=pa\ss\\word が JBOSS_ADMIN_PASSWORD=password に化けることを確認。 (2) さらに行末のバックスラッシュは行継続とみなされ、次の行と連結される。実測: JBOSS_A_PASSWORD=end\ と JBOSS_B_PASSWORD=next が 1 行に連結され、両方の秘密情報が同時に破壊されることを確認。 (3) $* での単語分割自体はバックスラッシュを分割対象としないため、破壊要因は read に限定される。 マスターパスワードはループを通らないため直接の被害は受けないが、JBOSS_ADMIN_PASSWORD 等が壊れる。
- **対処**: while IFS= read -r を用いる。根本的には compgen -e と ${!name} 方式へ置換し、値をテキスト行として読まない設計にする。

#### S6 ランチャスクリプト（elytron-tool.sh / add-user.sh） ― `OK`

- **現象**: eval を通ってもバックスラッシュは再解釈されない。
- **技術的根拠**: eval が再パースするのはテキスト "$@" であり、その展開結果は再パースされない。
- **対処**: 不要。

#### S7 実行時 standalone.sh ― `OK`

- **現象**: 環境変数値としてそのまま保持される。
- **技術的根拠**: コード外の注意として、Windows の PowerShell/cmd から設定する場合や JSON/YAML を経由する場合はエスケープ規則に従う必要がある。
- **対処**: 受け渡し経路のエスケープ規則に注意する。

#### S8 資格情報ストア実体（JCEKS + SunJCE PBE） ― `OK`

- **現象**: 印字可能 ASCII の範囲内 (0x20-0x7E) にあるため、SunJCE の PBE 鍵導出をそのまま通過する。（0x5C）
- **技術的根拠**: 0x00-0xFF の全 256 文字を JCEKS の SecretKeyEntry 格納で走査したところ、受理されたのは 0x20-0x7E の 95 文字のみであった（OpenJDK 17.0.11 で実測。当該チェックは com.sun.crypto.provider.PBEKey にあり OpenJDK 21 でも同一）。
- **対処**: 不要。

### 4.9 `|` （U+007C パイプ） ― 総合判定: **問題なし**

> | は演算子としてトークナイズ時にのみ認識される。展開結果は再トークナイズされないため常にデータ。

#### S1 BuildKit シークレット → 環境変数 ― `OK`

- **現象**: バイト列としてそのまま。
- **技術的根拠**: S1 はシェル解釈を介さない。
- **対処**: 不要。

#### S2 base.cli の式解決（WildFly ExpressionResolver） ― `OK`

- **現象**: 式構文・XML・JCEKS いずれでも非特殊。
- **技術的根拠**: 値が CLI 本文に現れないため、jboss-cli の字句解析も通らない。
- **対処**: 不要。

#### S3 base-env.sh での再 export ― `OK`

- **現象**: パイプ記号は演算子としてトークナイズ時にのみ認識される。
- **技術的根拠**: シェルの制御演算子はコマンド行の字句解析時に決定され、パラメータ展開の結果が再度トークナイズされることはない。したがって展開結果に含まれるパイプ記号は常にデータである。
- **対処**: 明示クォートを推奨。

#### S4 create-admin-user.sh ― `OK`

- **現象**: 単一 argv として渡る。
- **技術的根拠**: S4 はダブルクォート済み。
- **対処**: 不要。

#### S5 store_credentials.sh ― `OK`

- **現象**: read・正規表現・$* のいずれでもパイプ記号は変化しない。
- **技術的根拠**: read はパイプ記号を特別扱いしない。ERE のパイプ記号は選択（alternation）メタ文字だが、それはパターン側での意味であり、被検査文字列である ${line} 側では通常の文字。$* の単語分割は IFS に基づくためパイプ記号では分割されず、分割後の語が再トークナイズされないためパイプ演算子になることもない。実測: 値 p|q が正しくキャプチャされ、$* 経由でも単一引数のまま保持されることを確認。
- **対処**: 不要。

#### S6 ランチャスクリプト（elytron-tool.sh / add-user.sh） ― `OK`

- **現象**: eval を通っても再解釈されない。
- **技術的根拠**: "$@" の展開結果は再パースされない。
- **対処**: 不要。

#### S7 実行時 standalone.sh ― `OK`

- **現象**: 変化なし。
- **技術的根拠**: 受け渡し経路でもパイプ記号が問題になる実装は通常存在しない。
- **対処**: 不要。

#### S8 資格情報ストア実体（JCEKS + SunJCE PBE） ― `OK`

- **現象**: 印字可能 ASCII の範囲内 (0x20-0x7E) にあるため、SunJCE の PBE 鍵導出をそのまま通過する。（0x7C）
- **技術的根拠**: 0x00-0xFF の全 256 文字を JCEKS の SecretKeyEntry 格納で走査したところ、受理されたのは 0x20-0x7E の 95 文字のみであった（OpenJDK 17.0.11 で実測。当該チェックは com.sun.crypto.provider.PBEKey にあり OpenJDK 21 でも同一）。
- **対処**: 不要。

---

## 5. 特殊文字とは独立した欠陥一覧

| ID | 重要度 | 箇所 | 内容 | 影響 | 対処 |
|---|---|---|---|---|---|
| B-01 | **致命** | 1. Dockerfile | BuildKit の --mount は CSV 形式で解析される。カンマ直後の空白がキー名の一部となり、未知のキーとして拒否される。 | docker build が失敗する。 | 空白を除去し RUN --mount=type=secret,id=jboss_master_password,env=JBOSS_MASTER_PASSWORD,required=true \ とする。 |
| B-02 | **重大** | 5. store_credentials.sh | 秘密情報を行指向テキストとして再パースしている。LF 混入時の切り詰め・素通り・エイリアス注入、バックスラッシュのエスケープ消費、行末空白/タブのトリムがすべてここに集約されている。 | 改行を含むマスターパスワードで資格情報ストアへの任意エイリアス注入が成立する（実測で再現）。 | compgen -e による変数名列挙と ${!name} の間接展開に置換する。 |
| B-03 | **重大** | 5. store_credentials.sh / 4. create-admin-user.sh | パスワードがコマンドライン引数に載る。 | 同一 PID 名前空間の任意プロセスが ps -ef および /proc/<pid>/cmdline から平文を読める。コンテナ内で複数プロセスが動く構成では実害となる。 | jboss-cli の credential-store=EAPCS:add-alias(alias=..., secret-value="${env.JBOSS_ADMIN_PASSWORD}") 方式へ寄せ、argv からパスワードを排除する。base.cli が既にこの方式を採っているので設計の一貫性も向上する。 |
| B-04 | **重大** | 1. Dockerfile / 6. entrypoint.sh | BuildKit の env= はシークレットファイルの生バイト列を渡すため末尾 LF が混入しうる。実行時に別経路で渡した値と 1 バイトでも異なると一致しない。 | 起動時に資格情報ストアを開けず、Elytron の初期化に失敗してサーバが起動しない。原因表示が不親切で切り分けが困難。 | シークレットを printf '%s' で生成し、ビルド時と起動時の両方で CR/LF を検出して即 fail するアサートを置く。 |
| B-05 | **中** | 5. store_credentials.sh | 部分一致による除外。 | JBOSS_MASTER_PASSWORD_FILE のような別変数の行も落ちる。逆に、値の中にその文字列を含む無関係な変数の行も落ちる。 | そもそも除外はループ内の名前完全一致判定で行う。 |
| B-06 | **中** | 5. store_credentials.sh | 正規表現が未アンカーかつ .* が貪欲。 | MY_JBOSS_ADMIN_PASSWORD のような無関係な変数も一致する（実測で再現）。値に _PASSWORD= が含まれるとキャプチャ境界がずれ、エイリアス名と秘密値が両方壊れる（実測で再現）。 | 変数名の完全一致（case "$name" in JBOSS_*_PASSWORD) ）で判定する。 |
| B-07 | **中** | 6. entrypoint.sh | run-config-scripts.sh で 1 回、configuration-seed のコピー後にもう 1 回実行される。スクリプト冒頭に rm -f ${CREDENTIAL_STORE} があるため 1 回目の成果は破棄される。 | 無駄な処理であり、1 回目と 2 回目で環境が異なると挙動が非決定的になる。 | seed コピー後の 1 回に集約する。 |
| B-08 | **中** | 6. entrypoint.sh | 行継続が途切れているため install はコピー元のみを引数に取り、次行が独立したコマンドとして実行される。 | install がエラーになるか、war ファイルが配備されない。 | 各行末に \ を付ける。 |
| B-09 | **中** | 6. entrypoint.sh | exec のコマンドラインが -c standalone.xml で終端し、${JBOSS_SERVER_OPTS} が別コマンドとして解釈される。 | サーバオプションが一切渡らない。exec 済みなので後続行に到達しないケースもある。 | -c "standalone.xml" \ と継続し、${JBOSS_SERVER_OPTS} も分割意図があるなら配列化する。 |
| B-10 | **低** | 6. run_config_scripts.sh / entrypoint.sh | ファイル名の表記が 3 通りに揺れている。 | 存在しないパスを叩いて no such file になる。 | 名称を一本化する。 |
| B-11 | **低** | 2. base.cli | ビルド時（サーバ未起動）に jboss-cli.sh --file を実行するには先頭に embed-server、末尾に stop-embedded-server が必要。 | コントローラに接続できず CLI が失敗する。 | embed-server --server-config=standalone.xml --std-out=echo を先頭に置く。 |
| B-12 | **低** | 5. store_credentials.sh / 6. run_config_scripts.sh | パイプの右辺はサブシェルで実行されるため、ループ内の変数変更や exit が親シェルへ伝播しない。set -e も期待どおり働かない。 | 登録失敗を検知できず、壊れた資格情報ストアのまま起動が続行される。 | プロセス置換 done < <(...) を使うか、明示的に終了コードを集約する。 |
| B-13 | **低** | 5. store_credentials.sh | alias はシェル組み込みコマンド名と同名。変数としては合法だが可読性を損なう。 | 実害は無いが誤読を招く。 | cs_alias 等へ改名する。 |
| B-14 | **低** | 5. store_credentials.sh | 実際に登録したエイリアス名に関わらず admin-password と固定出力している。しかも呼び出し後ではなく関数内の末尾にある。 | ログが実態と乖離し、障害解析を誤らせる。 | 登録した実エイリアス名を出力する。 |
| B-15 | **低** | 3. base-env.sh | 未設定時に空文字で export されるため、未設定と空文字の区別が失われる。 | 後段が空パスワードで JCEKS を作成/オープンしようとして不可解なエラーになる。 | :"${JBOSS_MASTER_PASSWORD:?...}" で必須チェックしてから export する。 |
| B-16 | **低** | 5. store_credentials.sh 1 行目 | ログ文言のファイル名が create-credentials.sh となっているが、実体は store_credentials.sh。構文は正しく、実行に支障はない。 | 起動ログとファイル名が対応せず、障害解析時に追跡先を誤らせる。 | echo "startup shell executing ... startup/store_credentials.sh" とする。 |
| B-17 | **重大** | 1. Dockerfile | RUN --mount の env= オプションは Dockerfile frontend v1.10.0 以降でのみ有効。syntax 宣言が無いと既定 frontend のバージョンに依存する。 | frontend が古いと env= が解釈されず JBOSS_MASTER_PASSWORD が設定されない。 | ファイル先頭に # syntax=docker/dockerfile:1.10 を明記する。 |
| B-18 | **重大** | 1. Dockerfile（podman / buildah でビルドする場合） | podman の --secret における env= は「値の読み取り元のホスト環境変数」を指すソース指定であり、podman-build のドキュメントは RUN --mount=type=secret の宛先オプションとして id と target のみを挙げている。 | podman でビルドすると env= が機能せず、シークレットはファイルとしてのみマウントされる可能性がある。 | ビルドツールを確定する。podman を使うなら /run/secrets/<id> から読み、末尾 LF を除去する。 |
| B-19 | **重大** | 2. base.cli / 5. store_credentials.sh | JCEKS が受理するのは 0x20-0x7E のみだが、どこにも検証が無い。しかも空ストア作成は成功するため、失敗が最初のエイリアス登録まで遅延する。 | ビルドは成功し起動時に Password is not ASCII で落ちる。原因の切り分けが困難。 | ビルド時と起動時の両方で 0x20-0x7E の範囲チェックを行い、明示的なメッセージで落とす。 |

該当コードの詳細:

- **B-01** (1. Dockerfile): `RUN --mount=type=secret, id=jboss_master_password, env=...`
- **B-02** (5. store_credentials.sh): `printenv | grep -v JBOSS_MASTER_PASSWORD | while read line`
- **B-03** (5. store_credentials.sh / 4. create-admin-user.sh): `--password "${JBOSS_MASTER_PASSWORD}" / add-user.sh ... "${JBOSS_ADMIN_PASSWORD}"`
- **B-04** (1. Dockerfile / 6. entrypoint.sh): `ビルド時の JCEKS 作成と実行時の JCEKS オープン`
- **B-05** (5. store_credentials.sh): `grep -v JBOSS_MASTER_PASSWORD`
- **B-06** (5. store_credentials.sh): `[[ ${line} =~ JBOSS_(.*_PASSWORD)=(.*) ]]`
- **B-07** (6. entrypoint.sh): `store_credentials.sh を 2 回実行している`
- **B-08** (6. entrypoint.sh): `install -m 0644 \ の後の 2 行に継続行 \ が無い`
- **B-09** (6. entrypoint.sh): `-c "standalone.xml" の後に \ が無く ${JBOSS_SERVER_OPTS} が別行`
- **B-10** (6. run_config_scripts.sh / entrypoint.sh): `run_config_scripts.sh / run-config-scripts.sh / funconfig-scripts.sh`
- **B-11** (2. base.cli): `embed-server が無い`
- **B-12** (5. store_credentials.sh / 6. run_config_scripts.sh): `パイプライン中の while ループ`
- **B-13** (5. store_credentials.sh): `変数名 alias`
- **B-14** (5. store_credentials.sh): `echo "jboss_credential_store()... Adding alias: admin-password"`
- **B-15** (3. base-env.sh): `export JBOSS_MASTER_PASSWORD=${JBOSS_MASTER_PASSWORD}`
- **B-16** (5. store_credentials.sh 1 行目): `echo "startup shell executing ... startup/create-credentials.sh"`
- **B-17** (1. Dockerfile): `# syntax ディレクティブが無い`
- **B-18** (1. Dockerfile（podman / buildah でビルドする場合）): `--mount=type=secret,env= の宛先指定`
- **B-19** (2. base.cli / 5. store_credentials.sh): `パスワードの文字種チェックが無い`

---

## 6. 修正版コード

骨子は次の 5 点。

1. すべての変数展開をダブルクォートで囲む。
2. `read` には必ず `IFS= read -r` を用いる。
3. 関数の `$*` を `"$@"` に置換する。
4. `printenv` の行パースを廃し、`compgen -e` による変数名列挙 + 間接展開 `${!name}` に置換する。
5. 秘密情報を argv に載せず、jboss-cli の `${env....}` 式方式へ寄せる。

### 1. Dockerfile（ベースイメージ）

```bash
# syntax=docker/dockerfile:1.10
# ^ env= オプションは Dockerfile frontend v1.10.0 以降でのみ有効。必ず宣言すること。
#   podman/buildah でビルドする場合は env= が宛先として機能しない可能性があるため、
#   /run/secrets/jboss_master_password から読む形に書き換えること。

# --mount の内側にカンマ後の空白を入れない。
RUN --mount=type=secret,id=jboss_master_password,env=JBOSS_MASTER_PASSWORD,required=true \
    set -eu; \
    : "${JBOSS_MASTER_PASSWORD:?JBOSS_MASTER_PASSWORD is required}"; \
    if printf '%s' "$JBOSS_MASTER_PASSWORD" | LC_ALL=C grep -q '[^ -~]'; then \
        echo "FATAL: JBOSS_MASTER_PASSWORD must be printable ASCII (0x20-0x7E)." >&2; \
        echo "       JCEKS cannot store TAB/CR/LF/non-ASCII (SunJCE: Password is not ASCII)." >&2; \
        exit 1; \
    fi; \
    umask 077; \
    "${JBOSS_HOME}/bin/jboss-cli.sh" --echo-command --file="${JBOSS_HOME}/setup/base.cli"

# シークレットファイルは末尾 LF なしで生成すること:
#   printf '%s' "$PW" > ./secrets/jboss_master_password
#   docker build --secret id=jboss_master_password,src=./secrets/jboss_master_password .
```

### 2. base.cli

```bash
embed-server --server-config=standalone.xml --std-out=echo

/path=secrets.dir:add(path=security, relative-to=jboss.server.config.dir)

/subsystem=elytron/credential-store=EAPCS:add( \
    location="secrets.jceks", \
    relative-to=secrets.dir, \
    credential-reference={clear-text="${env.JBOSS_MASTER_PASSWORD}"}, \
    create=true)

stop-embedded-server

# 実値は CLI 本文に現れないため、CLI 字句解析・XML 構文・ログのいずれにも
# パスワードが露出しない。この方式を崩さないこと。
# --resolve-parameter-values は使用しないこと（式が実値に解決されて
# standalone.xml へ書き出され、XML 属性値正規化で TAB/LF/CR が空白化する）。
```

### 3. base-env.sh

```bash
#!/usr/bin/env bash
# 非クォートの export は bash/dash では偶然動くが仕様依存。必ずクォートする。

: "${JBOSS_ADMIN_USER:=admin}"
export JBOSS_ADMIN_USER

export JBOSS_ADMIN_PASSWORD="${JBOSS_ADMIN_PASSWORD:?JBOSS_ADMIN_PASSWORD is required}"
export JBOSS_MASTER_PASSWORD="${JBOSS_MASTER_PASSWORD:?JBOSS_MASTER_PASSWORD is required}"

# JCEKS(SunJCE PBE) の受理範囲は印字可能 ASCII 0x20-0x7E のみ。
# タブ・改行・復帰・非 ASCII はここで落とす（後段では原因が分からないエラーになる）。
for _v in JBOSS_ADMIN_PASSWORD JBOSS_MASTER_PASSWORD; do
    if printf '%s' "${!_v}" | LC_ALL=C grep -q '[^ -~]'; then
        echo "FATAL: ${_v} must consist of printable ASCII only (0x20-0x7E)." >&2
        exit 1
    fi
done
unset _v
```

### 4. create-admin-user.sh

```bash
#!/usr/bin/env bash
set -euo pipefail

echo "startup shell executing .. startup/create-admin-user.sh"

# -sc の引数もクォートする。
"${JBOSS_HOME}/bin/add-user.sh" \
    -sc "${JBOSS_HOME}/standalone/configuration" \
    "${JBOSS_ADMIN_USER}" \
    "${JBOSS_ADMIN_PASSWORD}"

# 注意: add-user.sh は引数にパスワードを取るため ps から見える。
# 恒久対策としては mgmt-users.properties をビルド時に生成するか、
# Elytron の filesystem-realm へ移行して jboss-cli 経由で登録する。
```

### 5. store_credentials.sh（全面書き換え）

```bash
#!/usr/bin/env bash
set -euo pipefail

echo "startup shell executing ... startup/store_credentials.sh"

SECRETS_DIR="${JBOSS_HOME}/standalone/configuration/security"
CREDENTIAL_STORE="${SECRETS_DIR}/secrets.jceks"

: "${JBOSS_MASTER_PASSWORD:?JBOSS_MASTER_PASSWORD is required}"

# JCEKS(SunJCE PBE) が受理するのは印字可能 ASCII 0x20-0x7E のみ。
# 範囲外だと空ストア作成は通り、最初の add-alias で Password is not ASCII になる。
# ここで先に落として原因を明示する。
assert_printable_ascii() {
    local name="$1" val="$2"
    if printf '%s' "${val}" | LC_ALL=C grep -q '[^ -~]'; then
        echo "FATAL: ${name} contains a character outside printable ASCII (0x20-0x7E)." >&2
        echo "       JCEKS credential store cannot store it (SunJCE: Password is not ASCII)." >&2
        exit 1
    fi
}
assert_printable_ascii JBOSS_MASTER_PASSWORD "${JBOSS_MASTER_PASSWORD}"

umask 077
mkdir -p "${SECRETS_DIR}"
rm -f "${CREDENTIAL_STORE}"

jboss_credential_store() {
    # $* ではなく "$@" を使う。これで空白・タブ・改行・グロブ文字を含む
    # 引数が分割・展開されなくなる。
    "${JBOSS_HOME}/bin/elytron-tool.sh" credential-store \
        --location "${CREDENTIAL_STORE}" \
        --password "${JBOSS_MASTER_PASSWORD}" \
        "$@"
}

jboss_credential_store --create

# printenv の行パースを廃止する。
# compgen -e は「環境変数名」だけを列挙する。変数名に = や改行は含まれ得ないため
# 行指向で安全に読める。値は間接展開 ${!name} で直接取得し、テキスト行を経由しない。
# これにより改行注入・バックスラッシュ消費・末尾空白トリムがすべて構造的に消滅する。
while IFS= read -r name; do
    [ "${name}" = "JBOSS_MASTER_PASSWORD" ] && continue
    case "${name}" in
        JBOSS_*_PASSWORD) ;;
        *) continue ;;
    esac

    secret="${!name}"
    assert_printable_ascii "${name}" "${secret}"

    key="${name#JBOSS_}"
    cs_alias="$(printf '%s' "${key}" | tr '[:upper:]_' '[:lower:]-')"

    echo "Adding alias: ${cs_alias}"
    jboss_credential_store --add "${cs_alias}" --secret "${secret}"
done < <(compgen -e | LC_ALL=C sort)
# プロセス置換にすることでループが親シェルで動き、set -e による失敗検知が効く。
```

### 5b. argv へのパスワード露出を無くす代替案（推奨）

```bash
# elytron-tool.sh は --password / --secret を argv で受け取るため ps から見える。
# jboss-cli 経由なら式を使えるので、パスワードは一切 argv に載らない。

# store_credentials.cli （jboss-cli --file= で実行）
/subsystem=elytron/credential-store=EAPCS:add-alias( \
    alias=admin-password, \
    secret-value="${env.JBOSS_ADMIN_PASSWORD}")

# 起動中サーバに対して実行する場合:
#   "${JBOSS_HOME}/bin/jboss-cli.sh" --connect --file=store_credentials.cli
# ビルド時に実行する場合は embed-server / stop-embedded-server で囲む。
#
# エイリアスを動的に決めたい場合は、上記 .cli をシェルで生成する。
# その際もパスワード実値は書き込まず ${env.VAR} 参照のみを書くこと。
```

### 6. run_config_scripts.sh

```bash
#!/usr/bin/env bash
set -euo pipefail

run_config_script() {
    local FILE="$1"
    echo "Running ${FILE}"
    case "${FILE}" in
        *.sh)
            # shellcheck disable=SC1090
            source "${FILE}"
            ;;
        *.cli)
            echo "processing ${JBOSS_HOME}/bin/jboss-cli.sh"
            "${JBOSS_HOME}/bin/jboss-cli.sh" --file="${FILE}"
            ;;
    esac
}

# $* ではなく "$@"。空白を含むパスでも壊れない。
for ARG in "$@"; do
    if [[ -d "${ARG}" ]]; then
        # find -print0 / read -d '' で改行を含むファイル名にも耐える。
        while IFS= read -r -d '' FILE; do
            echo "processing target file is ${FILE}"
            run_config_script "${FILE}"
        done < <(find "${ARG}" -type f -print0 | sort -z)
    else
        echo "processing target arg is ${ARG}"
        run_config_script "${ARG}"
    fi
done
```

### 7. entrypoint.sh

```bash
#!/usr/bin/env bash
set -euo pipefail

. "${JBOSS_HOME}/environment/base-env.sh"
. "${JBOSS_HOME}/setup/eap-env.sh"

# seed を先に展開してから資格情報ストアを 1 回だけ作る（rm -f による作り直しを避ける）。
cp -a "${JBOSS_HOME}/standalone/configuration-seed/." \
      "${JBOSS_HOME}/standalone/configuration/"

"${JBOSS_HOME}/bin/run-config-scripts.sh" "${JBOSS_HOME}/startup/create-admin-user.sh"
"${JBOSS_HOME}/bin/run-config-scripts.sh" "${JBOSS_HOME}/startup/store_credentials.sh"

install -m 0644 \
    "/online/deploy/iwinmichl.war" \
    "${JBOSS_HOME}/standalone/deployments/iwinmichl.war"

# JBOSS_SERVER_OPTS は配列で持つのが安全（文字列の非クォート展開は避ける）。
exec "${JBOSS_HOME}/bin/standalone.sh" \
    -b 0.0.0.0 \
    -bmanagement 0.0.0.0 \
    -c "standalone.xml" \
    ${JBOSS_SERVER_OPTS:-}
```

---

## 7. 実測検証ログ

GNU bash 5.3.9 / dash 上で実際に実行した結果。本書の判定根拠。

### E-01. export の非クォート展開で単語分割・グロブは起きるか

実行内容:

```bash
SRC='a b\tc'; export DST=${SRC}
```

結果:

```
DST=[a b\tc]（分割されず）。glob: SRC='*' でも DST=[*] のまま。改行: $'x\ny' も od -c で x \n y を保持。bash --posix / dash でも同結果。
```

意味: S3 は現状問題なし。ただし宣言コマンド規則への依存であり明示クォートすべき。

### E-02. read（IFS=・-r なし）は行末の空白／タブを削るか

実行内容:

```bash
printf 'JBOSS_ADMIN_PASSWORD=  lead and trail  \n' | while read line
```

結果:

```
read     -> [JBOSS_ADMIN_PASSWORD=  lead and trail]（末尾 2 空白が消失）\nIFS= read -r -> [JBOSS_ADMIN_PASSWORD=  lead and trail  ]（保持）。タブでも同様に末尾タブが消失。
```

意味: S5 で値末尾の空白／タブが静かに失われる。

### E-03. read（-r なし）はバックスラッシュを消費するか

実行内容:

```bash
printf 'JBOSS_ADMIN_PASSWORD=pa\\ss\\\\word\n' | while read line
```

結果:

```
read     -> [JBOSS_ADMIN_PASSWORD=password]（バックスラッシュが消滅）\nIFS= read -r -> [JBOSS_ADMIN_PASSWORD=pa\\ss\\word]（保持）
```

意味: S5 でバックスラッシュを含む秘密情報が破壊される。

### E-04. 行末バックスラッシュは次行と連結されるか

実行内容:

```bash
'JBOSS_A_PASSWORD=end\\' と 'JBOSS_B_PASSWORD=next' の 2 行を read
```

結果:

```
read     -> [JBOSS_A_PASSWORD=endJBOSS_B_PASSWORD=next]（1 行に連結）\nIFS= read -r -> 2 行として正しく分離
```

意味: 末尾がバックスラッシュのパスワードは隣の秘密情報まで巻き込んで破壊する。

### E-05. $* と "$@" の差

実行内容:

```bash
show(){ printf 'ARG[%s]\n' $*; }; show --add a --secret 'my pass word'
```

結果:

```
$*  -> ARG[--add] ARG[a] ARG[--secret] ARG[my] ARG[pass] ARG[word]（4 語に分解）\n"$@" -> ARG[--secret] ARG[my pass word]（保持）\nグロブ: --secret '*' が $* ではカレントディレクトリのファイル名 aaa bbb に展開された。\n改行: $'x\ny' が x と y に分解。\n一方 'p|q#r$s^t!u\\v' は $* でも単一引数のまま保持された。
```

意味: 空白・タブ・改行・グロブ文字のみが $* で壊れる。| # $ ^ ! \\ は壊れない。

### E-06. [[ =~ ]] の被検査文字列側でメタ文字は悪さをするか

実行内容:

```bash
line="JBOSS_ADMIN_PASSWORD=$v"; [[ ${line} =~ JBOSS_(.*_PASSWORD)=(.*) ]]
```

結果:

```
p#q / p$q / p^q / p!q / p q / p|q / p\\q / p*q はすべて BASH_REMATCH[2] に完全一致で格納された。\n一方 値 'a_PASSWORD=b' では key=[ADMIN_PASSWORD=a_PASSWORD] captured=[b] となり貪欲マッチでずれた。
```

意味: 記号自体は正規表現側で無害。ただし値に _PASSWORD= を含むとキャプチャが壊れる。

### E-07. 未アンカー正規表現は無関係な変数に一致するか

実行内容:

```bash
line='MY_JBOSS_ADMIN_PASSWORD=x'
```

結果:

```
一致し key=ADMIN_PASSWORD が得られた。
```

意味: 意図しない変数が資格情報ストアへ登録される。

### E-08. 改行入りマスターパスワードによるエイリアス注入

実行内容:

```bash
export JBOSS_MASTER_PASSWORD=$'Mast\nPART2\nJBOSS_FAKE_PASSWORD=injected' の状態で\nprintenv | grep -v JBOSS_MASTER_PASSWORD | while read line ... を実行
```

結果:

```
grep -v を素通りした行として PART2 と JBOSS_FAKE_PASSWORD=injected が残り、ループは\n  alias=fake-password secret=[injected]\n  alias=admin-password secret=[adminpw]\nの 2 件を登録対象として検出した。
```

意味: マスターパスワードの内容で資格情報ストアに任意エイリアスを注入できる。最重要の欠陥。

### E-09. # は展開結果でコメントになるか / ! は非対話で履歴展開されるか

実行内容:

```bash
V='#leading'; set -- --secret $V / bash -c 'V="a!b"; ...'
```

結果:

```
ARG[--secret] ARG[#leading]（コメント化しない）。非対話シェルでは set -H を付けても a!b のまま。
```

意味: # と ! は本コードで問題なし。

### E-10. 提示された store_credentials.sh は構文的に妥当か

実行内容:

```bash
提示コード（echo の閉じダブルクォートあり）を bash -n に掛ける
```

結果:

```
exit=0。構文エラーなし。スクリプトは正常に実行される。
```

意味: 当初 echo の閉じクォート欠落を指摘したが誤りであった。構文上の問題は存在しない。以降の指摘はすべて実行時の挙動に関するもの。

### E-11. 実スクリプトでの記号通過テスト（elytron-tool.sh をスタブ化して argv を観測）

実行内容:

```bash
JBOSS_ADMIN_PASSWORD に各記号を設定し store_credentials.sh をそのまま実行。
elytron-tool.sh が受け取った argv を出力。
```

結果:

```
input=[p#q] -> --secret [p#q]        …保持
input=[p$q] -> --secret [p$q]        …保持
input=[p^q] -> --secret [p^q]        …保持
input=[p!q] -> --secret [p!q]        …保持
input=[p|q] -> --secret [p|q]        …保持
input=[p\q] -> --secret [pq]         …バックスラッシュ消失
input=[p q] -> --secret [p] [q]      …2 引数に分裂
input=[p<TAB>q] -> --secret [p] [q]  …2 引数に分裂
```

意味: # $ ^ ! | は実スクリプトでも無傷で通過する。\ は read の -r 欠落で消え、空白とタブは $* の単語分割で分裂する。判定表と完全に一致した。

### E-12. 実スクリプトでの複合破壊（空白 + バックスラッシュ + 末尾タブ）

実行内容:

```bash
JBOSS_ADMIN_PASSWORD='ad min\pw<TAB>' を設定し store_credentials.sh を実行
```

結果:

```
elytron-tool ARGV: ... [--add] [admin-password] [--secret] [ad] [minpw]
```

意味: 空白による分裂・バックスラッシュの消費・末尾タブのトリムが 1 回の実行で同時に起きた。本来 1 つであるべき秘密値が [ad] と [minpw] の 2 引数になり、値も元と異なる。

### E-13. 実スクリプトでの改行注入（エンドツーエンド）

実行内容:

```bash
JBOSS_MASTER_PASSWORD=$'Mast\nJBOSS_FAKE_PASSWORD=injected' を設定し store_credentials.sh を実行
```

結果:

```
elytron-tool ARGV: ... [--add] [fake-password] [--secret] [injected]
elytron-tool ARGV: ... [--add] [admin-password] [--secret] [adminpw]
```

意味: マスターパスワードに仕込んだ 2 行目が grep -v を素通りして正規表現に一致し、実在しない環境変数 JBOSS_FAKE_PASSWORD 由来のエイリアス fake-password が実際に登録された。スタブではなく提示コードそのものでの再現であり、資格情報ストアへの注入が成立する。

### E-14. JCEKS は各記号を含むパスワードを受理するか（OpenJDK 17.0.11 で実測）

実行内容:

```bash
JCEKS キーストアを作成し SecretKeyEntry を同一パスワードで保護して格納 →\n保存 → 再読込 → 取り出し、のラウンドトリップを実施
```

結果:

```
#  p#q      OK    round-trip ok\n$  p$q      OK    round-trip ok\n^  p^q      OK    round-trip ok\n!  p!q      OK    round-trip ok\n|  p|q      OK    round-trip ok\n\\  p\\q      OK    round-trip ok\nSP p q      OK    round-trip ok\n末尾SP pq   OK    round-trip ok\nTAB p<TAB>q FAIL  KeyStoreException: Password is not ASCII\nLF  p<LF>q  FAIL  KeyStoreException: Password is not ASCII\n非ASCII péq FAIL  KeyStoreException: Password is not ASCII\n非ASCII pパq FAIL KeyStoreException: Password is not ASCII
```

意味: # $ ^ ! | \\ 半角スペース（末尾含む）は資格情報ストアでも問題ない。タブ・改行・非 ASCII は格納自体が不可能。

### E-15. どの操作で失敗するのか、受理される文字コード範囲はどこまでか

実行内容:

```bash
load(null) / setEntry(SecretKeyEntry) / store() / reload() / getEntry() のどこで例外が出るかを切り分け、\n続けて 0x00-0xFF の全 256 文字について格納可否を走査
```

結果:

```
TAB(0x09)     -> setEntry(SecretKey): InvalidKeySpecException / Password is not ASCII\nLF(0x0A)      -> setEntry(SecretKey): InvalidKeySpecException / Password is not ASCII\nCR(0x0D)      -> setEntry(SecretKey): InvalidKeySpecException / Password is not ASCII\nSPACE(0x20)   -> OK\ne-acute(0xE9) -> setEntry(SecretKey): InvalidKeySpecException / Password is not ASCII\n受理される連続範囲: 0x20 - 0x7E　受理された文字数: 95 / 256
```

意味: 失敗するのは秘密鍵エントリの格納時のみ。受理範囲は印字可能 ASCII に正確に一致する。

### E-16. 秘密鍵エントリを含まない空ストアなら通ってしまうか

実行内容:

```bash
SecretKeyEntry を入れずに JCEKS の store() と load() のみを実行
```

結果:

```
TAB(0x09)     -> OK\nLF(0x0A)      -> OK\nCR(0x0D)      -> OK\nSPACE(0x20)   -> OK\ne-acute(0xE9) -> OK
```

意味: ストア整合性 MAC は任意の文字を受理する。したがって base.cli の create=true による空ストア作成はビルド時に成功し、失敗は最初のエイリアス登録まで遅延する。ビルドは通るのに起動で落ちる最悪の失敗形態。

---

## 8. 推奨パスワードポリシー

| 区分 | 対象 | 根拠 |
|---|---|---|
| **禁止（技術的に不可能）** | `タブ (0x09) / 改行 (0x0A) / 復帰 (0x0D) / 非 ASCII` | OpenJDK の SunJCE が JCEKS 秘密鍵エントリの PBE パスワードを印字可能 ASCII (0x20-0x7E) に限定するため、資格情報ストアに格納できない（実測）。シェル側をどれだけ修正しても回避できない。 |
| **許可される文字集合** | `0x20-0x7E の 95 文字（半角スペースを含む印字可能 ASCII 全て）` | JCEKS が受理する範囲と完全に一致する。この範囲内であれば # $ ^ ! \| \ 半角スペース を含め、シェル側を修正すればすべて安全に扱える。 |
| **許可** | `# $ ^ ! \| ( ) [ ] { } < > ? * + - _ = . , : ; / @ % & ~ ' " `` | 現行コードでも修正後コードでも安全に通過する。$ は環境変数を設定する側（compose / K8s）でのエスケープのみ注意。 |
| **修正後に許可** | `\ （バックスラッシュ）` | 現行コードでは read の -r 欠落により破壊される。IFS= read -r への修正、または compgen -e 方式への置換後は安全。 |
| **修正後に許可（先頭・末尾を除く）** | `半角スペース / タブ（値の途中のみ）` | 現行コードでは $* の単語分割で破壊される。"$@" 化と compgen -e 方式で解決する。ただし先頭・末尾の空白類は受け渡し経路（--env-file、CI 変数欄）でトリムされる実装があるため、修正後も禁止を推奨。 |
| **非推奨** | `タブ（位置を問わず）` | 画面上不可視で、値が壊れても検知できない。YAML / .env / CI 入力欄で空白へ変換されたり消えたりする。 |
| **禁止** | `LF (\n) / CR (\r)` | printenv 行パースの切り詰め、grep -v の素通り、資格情報ストアへのエイリアス注入（実測で再現）、XML 属性値正規化による空白化、--env-file で表現不可能、ビルド時と実行時のバイト不一致。コード修正でも運用上のリスクが残るため一律禁止。 |
| **禁止** | `NUL (\0)` | 環境変数・argv とも NUL 区切りのため、そもそも値として格納できない。 |
| **運用ルール** | `シークレットファイルは末尾 LF なしで生成する` | printf '%s' "$PW" > secret_file。echo を使うと LF が混入し、ビルド時と実行時の値が食い違う。 |
| **運用ルール** | `ビルド時と実行時に同一バイト列を渡す` | BuildKit secret と実行時の環境変数で経路が異なるため、CI で同一ソースから配布し、起動時にハッシュ等で一致を検証する。 |
| **運用ルール** | `argv にパスワードを載せない` | ps -ef / /proc/<pid>/cmdline から読める。jboss-cli の ${env....} 式方式へ寄せる。 |

---

## 9. 実行環境固有の分析 ― JBoss EAP 8.1 / UBI 9.8 / OpenJDK 21

本章の内容はバージョンに依存する。とくに EV-01 は、シェル側をどれだけ修正しても越えられない上限を定める。

### 9.1 環境の前提

| 構成要素 | バージョン | 本分析に効いてくる性質 |
|---|---|---|
| アプリケーションサーバ | JBoss EAP 8.1 | Elytron のみ（legacy security subsystem は EAP 8 で削除済み）。credential-store の既定実装は KeyStoreCredentialStore で、実体は JCEKS キーストア。add-user.sh は properties-realm 用に引き続き同梱される。 |
| ベースイメージ | UBI 9.8 (RHEL 9 系) | /bin/sh は bash へのシンボリックリンク（RHEL 9 に dash は同梱されない）。bash は 5.1.8 系。したがって Dockerfile の RUN 既定シェル /bin/sh -c も bash であり、export の宣言コマンド規則・[[ ]]・BASH_REMATCH・compgen はすべて利用できる。 |
| JVM | OpenJDK 21 (Red Hat build) | JCEKS の秘密鍵エントリは SunJCE の PBEWithMD5AndTripleDES で保護される。その鍵導出 (com.sun.crypto.provider.PBEKey) はパスワードを印字可能 ASCII に限定する。これが本環境における最も強い制約。 |
| 資格情報ストア | secrets.jceks (JCEKS) | ストア整合性は SHA-1 ベースの MAC、各エントリは PBE で保護される。両者でパスワードの受理範囲が異なる点が重要（後述 EV-01）。 |

### 9.2 環境固有の指摘

#### EV-01 [最重要] JCEKS の秘密鍵エントリ保護は印字可能 ASCII (0x20-0x7E) しか受理しない

- **根拠**: SunJCE の PBEWithMD5AndTripleDES 鍵導出（com.sun.crypto.provider.PBEKey）が、パスワード中の文字を 0x20〜0x7E に限定している。範囲外の文字が 1 つでもあると InvalidKeySpecException: Password is not ASCII で失敗する。0x00-0xFF の全 256 文字を走査し、受理されたのは 0x20-0x7E の 95 文字のみであることを実測した。
- **影響**: タブ (0x09)・改行 (0x0A)・復帰 (0x0D) は JBOSS_MASTER_PASSWORD に使用できない。シェル側をどれだけ修正しても、資格情報ストアそのものが受け付けない。非 ASCII（日本語・アクセント付きラテン文字など）も同様に使用できない。半角スペース (0x20) とバックスラッシュ (0x5C) は範囲内のため JCEKS 層では問題ない。
- **対処**: パスワードを 0x20-0x7E に限定する。ポリシーとしてタブ・改行・復帰・非 ASCII を禁止する。

#### EV-02 [最重要] 空のストア作成は成功し、最初のエイリアス登録で初めて失敗する

- **根拠**: キーストアの整合性 MAC は任意の文字を受理するのに対し、秘密鍵エントリの PBE 保護のみが ASCII 制限を持つ。SecretKeyEntry を入れずに store()/load() する経路ではタブ・改行・非 ASCII でも すべて成功することを実測した。失敗が起きるのは setEntry(SecretKeyEntry) の時点である。
- **影響**: base.cli の create=true による空ストア作成はビルド時に成功してしまう。その後の store_credentials.sh の --add、あるいは実行時の最初の資格情報登録で初めて Password is not ASCII が出る。ビルドは通るのに起動時に落ちるという、最も切り分けづらい失敗の仕方をする。
- **対処**: ビルド時に空ストア作成だけで検証を済ませない。ダミーエイリアスを 1 件登録・削除して疎通確認するか、シェル側で 0x20-0x7E の範囲チェックを先に行う。

#### EV-03 [重大] RUN --mount の env= オプションは Dockerfile frontend v1.10.0 以降が必要

- **根拠**: docker 公式リファレンスは env について "Mount the secret to an environment variable instead of a file, or both. (since Dockerfile v1.10.0)" と明記している。提示された Dockerfile には # syntax ディレクティブが無く、既定 frontend が v1.10.0 未満だと env= が解釈されない。
- **影響**: env= が無視されると JBOSS_MASTER_PASSWORD が設定されないまま RUN が走る。: "${JBOSS_MASTER_PASSWORD:?}" のチェックがあるので即失敗するが、原因が secret 未指定なのか frontend 古さなのか切り分けにくい。
- **対処**: Dockerfile 先頭に # syntax=docker/dockerfile:1.10 （以降のバージョンでも可）を明記する。

#### EV-04 [重大] podman / buildah でビルドする場合 env= の意味が異なる

- **根拠**: podman の --secret オプションにおける env= は「シークレット値の読み取り元となるホスト側の環境変数名」を指すソース指定であり、docker の Containerfile 側 env=（宛先指定）とは意味が異なる。podman-build のドキュメントは RUN --mount=type=secret について id と target/dst/destination のみを記載しており、env= を宛先として挙げていない。UBI ベースの構成では podman build が使われることが多い。
- **影響**: podman でビルドすると env= が宛先として機能せず、環境変数が設定されない可能性がある。その場合 /run/secrets/<id> にファイルとしてのみマウントされる。
- **対処**: ビルドに使うツールを確定させる。podman を使うなら env= に依存せず JBOSS_MASTER_PASSWORD="$(cat /run/secrets/jboss_master_password)" の形でファイルから読む。その際も末尾 LF の除去が必要（EV-05）。

#### EV-05 [重大] シークレットファイル末尾の LF が JCEKS の ASCII 制限に直撃する

- **根拠**: BuildKit も podman もシークレットの内容をバイト列のまま渡す。echo で生成したファイルには末尾に LF が付く。従来これは「ビルド時と実行時で値が食い違う」という問題だったが、本環境では EV-01 により LF そのものが資格情報ストアに格納できないため、Password is not ASCII という別のエラーとして現れる。
- **影響**: 末尾 LF 付きのシークレットを使うと、空ストア作成は通り、エイリアス登録で失敗する。エラーメッセージからは末尾 LF が原因だと読み取れない。
- **対処**: printf '%s' でシークレットを生成する。読み込み側でも JBOSS_MASTER_PASSWORD="${JBOSS_MASTER_PASSWORD%$'\n'}" 等で末尾 LF を除去し、さらに 0x20-0x7E の範囲チェックを行う。

#### EV-06 [中] EAP 8.1 の elytron-tool.sh は eval と '"$@"' を使っており値は再展開されない

- **根拠**: upstream wildfly-core の elytron-tool.sh 末尾は eval \"$JAVA\" $JAVA_OPTS -jar ... org.wildfly.security.elytron-tool '"$@"' の形。eval が再パースするのはテキスト "$@" であり、位置パラメータの展開結果は再展開されない。
- **影響**: S6 の判定（全文字 OK）は EAP 8.1 でもそのまま成立する。ただし $JAVA_OPTS は非クォートのまま eval に渡るため、そちらに特殊文字を入れると危険。
- **対処**: パスワード側の対処は不要。JAVA_OPTS に信頼できない値を入れないこと。

#### EV-07 [中] コンテナのロケール未設定時、JVM の sun.jnu.encoding が ASCII になる

- **根拠**: JDK 18 以降 file.encoding は UTF-8 が既定になったが、コマンドライン引数・環境変数・ファイルパスの復号に使われる sun.jnu.encoding はプラットフォームのロケールに従う。LANG / LC_ALL が未設定または C / POSIX の場合 ANSI_X3.4-1968 (ASCII) となり、非 ASCII バイトは ? に置換される。
- **影響**: System.getenv() および argv 経由で渡したパスワードが壊れる。ただし本環境では EV-01 により非 ASCII は元々使用できないため、0x20-0x7E に限れば実害は生じない。
- **対処**: 非 ASCII を使わない運用であれば対処不要。確認する場合は podman exec <ctr> java -XshowSettings:properties -version 2>&1 | grep jnu。

#### EV-08 [参考] FIPS モードでは JCEKS 自体が利用できない

- **根拠**: RHEL 9 を FIPS モードで運用する場合、MD5 を用いる PBEWithMD5AndTripleDES が使用できないため JCEKS 形式の資格情報ストアは作成できない。
- **影響**: fips-mode-setup --enabled のホスト上では、本構成はそもそも起動しない。
- **対処**: FIPS 環境では credential-store の type を変更するか、EAP 8 の secret-key-credential-store / 暗号化式 (${ENC::...}) への移行を検討する。

### 9.3 コンテナ内での確認コマンド

```bash
# 1) /bin/sh の実体と bash のバージョン
podman exec <ctr> sh -c 'ls -l /bin/sh; bash --version | head -1'

# 2) JVM のエンコーディング設定（非 ASCII を扱う場合のみ関係する）
podman exec <ctr> java -XshowSettings:properties -version 2>&1 \
    | grep -E 'sun.jnu.encoding|file.encoding|java.version'

# 3) JCEKS が受け付けるパスワードかを事前に判定する（シェルだけで完結）
printf '%s' "$JBOSS_MASTER_PASSWORD" | LC_ALL=C grep -q '[^ -~]' \
    && echo 'NG: printable ASCII (0x20-0x7E) 以外を含む' \
    || echo 'OK: JCEKS に格納可能'

# 4) 資格情報ストアに実際に 1 件登録できるかを確認する
#    空ストア作成だけでは検証にならない（EV-02）
"${JBOSS_HOME}/bin/elytron-tool.sh" credential-store \
    --location /tmp/probe.jceks --password "$JBOSS_MASTER_PASSWORD" --create
"${JBOSS_HOME}/bin/elytron-tool.sh" credential-store \
    --location /tmp/probe.jceks --password "$JBOSS_MASTER_PASSWORD" \
    --add probe --secret dummy
rm -f /tmp/probe.jceks
```
