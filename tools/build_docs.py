#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JBOSS_MASTER_PASSWORD 特殊文字影響分析 の Markdown / Excel を単一データから生成する。

    python3 tools/build_docs.py

データは tools/analysis_data.json に置く。マトリクスは第 4 章の詳細から自動導出するため、
判定が md と xlsx の間や章の間で食い違うことは構造的に起きない。
"""
import json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(HERE, "analysis_data.json")
BASENAME = "JBOSS_MASTER_PASSWORD_特殊文字分析"

d = json.load(open(DATA, encoding="utf-8"))
CHARS  = d["chars"]
STAGES = d["stages"]
SIDX   = {s["id"]: s for s in STAGES}

# ------------------------------------------------------------------ 章の導入文
INTRO = {
 2: "どの文字がどこで壊れるかは、値が各ステージで「バイト列として渡るか」「テキストとして再パースされるか」で決まる。\n"
    "A1-A3 はパラメータストアの登録・取得・受け渡しであり、S1 より前段にある。"
    "AWS 自体は値を一切検証しないため、事故の芽はここで作られ、発芽するのは S5 / S8 である。",
 3: "凡例: `OK` = 値が一切変化しない / `△` = 条件次第で破綻、または運用経路で事故る / `NG` = 値が破壊される、処理が失敗する",
 5: "これらは文字種に関わらず常に問題となる。",
 6: "骨子は次の 8 点。\n\n"
    "1. パラメータストアへの登録前に 0x20-0x7E の範囲チェックを行い、登録そのものを拒否する。\n"
    "2. 範囲チェックに `grep` を使わない（行指向のため改行を見逃す）。`od` で 16 進化してから判定する。\n"
    "3. 取得は `--output json` + `jq -j -r` で行い、`--output text` と `$( )` の組み合わせを使わない。\n"
    "4. すべての変数展開をダブルクォートで囲む。\n"
    "5. `read` には必ず `IFS= read -r` を用いる。\n"
    "6. 関数の `$*` を `\"$@\"` に置換する。\n"
    "7. `printenv` の行パースを廃し、`compgen -e` による変数名列挙 + 間接展開 `${!name}` に置換する。\n"
    "8. 秘密情報を argv に載せず、jboss-cli の `${env....}` 式方式へ寄せる（実値の直書きは禁止）。",
 7: "GNU bash 5.2.21 / dash / OpenJDK 21.0.10 / AWS CLI 1.46.1 + botocore 1.43 / jboss-dmr 1.6.1.Final 上で"
    "実際に実行した結果。本書の判定根拠。",
 8: "修正前提の可否と運用ルールを分けて示す。",
 9: "本章の内容はバージョンに依存する。とくに EV-01 と EV-09 は、シェル側をどれだけ修正しても越えられない上限を定める。",
}

# ================================================================== Markdown
def esc(t):
    """表セル用。改行を <br> に、| をエスケープする。"""
    if t is None: return ""
    return str(t).replace("|", "\\|").replace("\n", "<br>")

def table(headers, rows):
    out = ["| " + " | ".join(headers) + " |",
           "|" + "---|" * len(headers)]
    for r in rows:
        out.append("| " + " | ".join(esc(c) for c in r) + " |")
    return "\n".join(out)

def build_md():
    o = []
    w = o.append
    w("# %s" % d["meta"]["title"])
    w("")
    w("対象文字・パターン: %s" % d["meta"]["targets"])
    w("")
    w("- 分析日: %s" % d["meta"]["date"])
    w("- 改訂: %s" % d["meta"]["revised"])
    w("- 検証環境: %s" % d["meta"]["verify_env"])
    w("- 本書の判定は推測ではなく、第 7 章の実測結果に基づく。")
    w("- 「`\\n` と打ったときに何が保存され、何が起動時に届くのか」は第 10 章の対応表に一覧した。")
    w("")
    w("---")
    w("")
    # ---- 1
    w("## 1. 結論サマリ")
    w("")
    w("### 1.1 文字・パターン別の総合判定")
    w("")
    w(table(["文字・パターン", "表記", "総合判定", "破綻する箇所", "要約"],
            [["`%s`" % c["key"], c["notation"], "**%s**" % c["verdict"], c["break_at"] or "—", c["summary"]]
             for c in CHARS]))
    w("")
    w("### 1.2 特殊文字とは独立に、先に直すべき重大事項")
    w("")
    for p in d["priority_items"]:
        w("#### [%s] %s" % (p["severity"], p["title"]))
        w("")
        w("- **内容**: %s" % p["content"])
        w("- **対処**: %s" % p["remedy"])
        w("")
    w("---")
    w("")
    # ---- 2
    w("## 2. パスワードが通過する %d のステージ" % len(STAGES))
    w("")
    w(INTRO[2])
    w("")
    for s in STAGES:
        w("### %s. %s" % (s["id"], s["name"]))
        w("")
        w("```")
        w(s["code"])
        w("```")
        w("")
        w("- **値の扱われ方**: %s" % s["handling"])
        w("- **着眼点**: %s" % s["focus"])
        w("")
    w("---")
    w("")
    # ---- 3
    w("## 3. 文字 × ステージ 判定マトリクス")
    w("")
    w(INTRO[3])
    w("")
    w(table(["文字・パターン"] + [s["id"] for s in STAGES] + ["総合"],
            [["`%s`" % c["key"]] + [d["matrix"][c["key"]][s["id"]] for s in STAGES] + ["**%s**" % c["verdict"]]
             for c in CHARS]))
    w("")
    for s in STAGES:
        w("- **%s** = %s" % (s["id"], s["name"]))
    w("")
    w("---")
    w("")
    # ---- 4
    w("## 4. 文字・パターン別 詳細分析")
    w("")
    for i, c in enumerate(CHARS, 1):
        w("### 4.%d `%s` （%s） ― 総合判定: **%s**" % (i, c["key"], c["notation"], c["verdict"]))
        w("")
        w("> %s" % c["summary"])
        w("")
        for x in [x for x in d["details"] if x["char"] == c["key"]]:
            w("#### %s ― `%s`" % (x["stage"], x["verdict"]))
            w("")
            w("- **現象**: %s" % x["phenomenon"])
            w("- **技術的根拠**: %s" % x["rationale"])
            w("- **対処**: %s" % x["remedy"])
            w("")
    w("---")
    w("")
    # ---- 5
    w("## 5. 特殊文字とは独立した欠陥一覧")
    w("")
    w(INTRO[5])
    w("")
    w(table(["ID", "重要度", "箇所", "内容", "影響", "対処"],
            [[b["id"], "**%s**" % b["severity"], b["place"], b["content"], b["impact"], b["remedy"]]
             for b in d["defects"]]))
    w("")
    w("該当コードの詳細:")
    w("")
    for b in d["defects"]:
        w("- **%s** (%s): `%s`" % (b["id"], b["place"], b["code"]))
    w("")
    w("---")
    w("")
    # ---- 6
    w("## 6. 修正版コード")
    w("")
    w(INTRO[6])
    w("")
    for f in d["fixes"]:
        w("### %s" % f["file"])
        w("")
        w("```bash")
        w(f["code"])
        w("```")
        w("")
    w("---")
    w("")
    # ---- 7
    w("## 7. 実測検証ログ")
    w("")
    w(INTRO[7])
    w("")
    for e in d["experiments"]:
        w("### %s. %s" % (e["id"], e["title"]))
        w("")
        w("実行内容:")
        w("")
        w("```bash")
        w(e["command"])
        w("```")
        w("")
        w("結果:")
        w("")
        w("```")
        w(e["result"])
        w("```")
        w("")
        w("意味: %s" % e["meaning"])
        w("")
    w("---")
    w("")
    # ---- 8
    w("## 8. 推奨パスワードポリシー")
    w("")
    w(INTRO[8])
    w("")
    w(table(["区分", "対象", "根拠"],
            [["**%s**" % p["category"], "`%s`" % p["target"], p["rationale"]] for p in d["policy"]]))
    w("")
    w("---")
    w("")
    # ---- 9
    w("## 9. 実行環境固有の分析 ― JBoss EAP 8.1 / UBI 9.8 / OpenJDK 21 / AWS パラメータストア")
    w("")
    w(INTRO[9])
    w("")
    w("### 9.1 環境の前提")
    w("")
    w(table(["構成要素", "バージョン", "本分析に効いてくる性質"],
            [[p["component"], p["version"], p["property"]] for p in d["env_premise"]]))
    w("")
    w("### 9.2 環境固有の指摘")
    w("")
    for ev in d["env_items"]:
        head, _, body = ev["body"].partition("\n\n")
        w("#### %s [%s] %s" % (ev["id"], ev["severity"], head))
        w("")
        for chunk in (body + "\n\n" + (ev["impact"] or "")).split("\n\n"):
            chunk = chunk.strip()
            if not chunk: continue
            m = re.match(r"^【(.+?)】(.*)$", chunk, re.S)
            if m: w("- **%s**: %s" % (m.group(1), m.group(2).strip()))
            else: w("- %s" % chunk)
        w("")
    w("### 9.3 コンテナ内での確認コマンド")
    w("")
    w("```bash")
    w(d["env_commands"])
    w("```")
    w("")
    w("---")
    w("")
    # ---- 10
    w("## 10. 入力表記ゆれ対応表 ― 何を打つと何が保存され、何が起動時に届くか")
    w("")
    for i, ln in enumerate(d["notation_note"].split("\n")):
        if ln.startswith("・"):
            if i and not d["notation_note"].split("\n")[i - 1].startswith("・"): w("")
            w("- %s" % ln[1:])
        else:
            w(ln)
    w("")
    w(table(["入力した表記", "登録経路", "保存される値 (hex)", "推奨経路で届く値 (hex)",
             "現行経路で届く値 (hex)", "JCEKS", "現行 S5 の結果", "総合判定"],
            [[r["typed"], r["route"], r["stored"], r["env_recommended"], r["env_current"],
              r["jceks"], r["s5"], r["verdict"]] for r in d["notation_table"]]))
    w("")
    return "\n".join(o) + "\n"

# ================================================================== Excel
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

FONT = "Meiryo UI"
BLACK, DARK, MID, GREY, BAND, WHITE = "000000", "262626", "404040", "BFBFBF", "F2F2F2", "FFFFFF"
THIN = Side(style="thin", color="BFBFBF")
BORDER = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)

def fill(c): return PatternFill("solid", fgColor=c)

class Sheet:
    def __init__(self, wb, name, title, subtitle, widths):
        self.ws = wb.create_sheet(name)
        self.n = len(widths)
        for i, wdt in enumerate(widths, 1):
            self.ws.column_dimensions[get_column_letter(i)].width = wdt
        self._frozen = False
        self._merge_row(1, title, 14, True, BLACK, WHITE, 30)
        self._merge_row(2, subtitle, 9, False, WHITE, MID, 26)
        self.r = 4

    def _merge_row(self, r, text, size, bold, bg, fg, h):
        c = self.ws.cell(r, 1, text)
        c.font = Font(name=FONT, size=size, bold=bold, color=fg)
        c.fill = fill(bg)
        c.alignment = Alignment(horizontal="left", vertical="center", wrap_text=True)
        self.ws.merge_cells(start_row=r, start_column=1, end_row=r, end_column=self.n)
        self.ws.row_dimensions[r].height = h

    def section(self, text):
        self._merge_row(self.r, text, 11, True, "595959", WHITE, 22)
        self.r += 1

    def header(self, labels, h=24, merges=()):
        for i, t in enumerate(labels, 1):
            c = self.ws.cell(self.r, i, t)
            c.font = Font(name=FONT, size=10, bold=True, color=WHITE)
            c.fill = fill(DARK)
            c.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
            c.border = BORDER
        self.ws.row_dimensions[self.r].height = h
        for a, b in merges:
            self.ws.merge_cells(start_row=self.r, start_column=a, end_row=self.r, end_column=b)
        if not self._frozen:
            self.ws.freeze_panes = self.ws.cell(self.r + 1, 1)
            self._frozen = True
        self.r += 1

    def row(self, values, band=False, h=None, center=(), verdicts=(), mono=(), bold=(), size=9, merges=()):
        for i, v in enumerate(values, 1):
            c = self.ws.cell(self.r, i, v)
            bg, fg, bd = (BAND if band else None), BLACK, (i in bold)
            if i in verdicts:
                if v == "NG":   bg, fg, bd = MID, WHITE, True
                elif v == "△":  bg, fg, bd = GREY, BLACK, True
                else:           bd = True
            if bg: c.fill = fill(bg)
            c.font = Font(name=FONT, size=size, bold=bd, color=fg)
            if i in mono:
                c.font = Font(name="Consolas", size=8, bold=bd, color=fg)
            c.alignment = Alignment(horizontal=("center" if (i in center or i in verdicts) else "left"),
                                    vertical=("center" if (i in center or i in verdicts) else "top"),
                                    wrap_text=True)
            c.border = BORDER
        for a, b in merges:
            self.ws.merge_cells(start_row=self.r, start_column=a, end_row=self.r, end_column=b)
        if h: self.ws.row_dimensions[self.r].height = h
        self.r += 1

    def separator(self):
        for i in range(1, self.n + 1):
            self.ws.cell(self.r, i).fill = fill(DARK)
        self.ws.row_dimensions[self.r].height = 6
        self.r += 1

    def blank(self):
        self.r += 1

def est_height(values, widths, base=30, per=15, cap=340):
    """列幅に対する文字数からおおよその行高を見積もる。"""
    need = 1
    for v, wdt in zip(values, widths):
        if not isinstance(v, str): continue
        lines = 0
        for ln in v.split("\n"):
            lines += max(1, -(-len(ln) * 2 // max(int(wdt), 4)))
        need = max(need, lines)
    return min(cap, max(base, need * per))

def build_xlsx(path):
    wb = Workbook(); wb.remove(wb.active)
    meta_sub = ("対象: %s\u3000\u3000分析日: %s\n改訂: %s\n検証環境: %s"
                % (d["meta"]["targets"], d["meta"]["date"], d["meta"]["revised"], d["meta"]["verify_env"]))

    # ---- 00 結論サマリ
    W = [22, 26, 28, 30, 92]
    s = Sheet(wb, "00_結論サマリ", "%s ― 結論サマリ" % d["meta"]["title"], meta_sub, W)
    s.ws.row_dimensions[2].height = 52
    s.section("1. 文字・パターン別の総合判定")
    s.header(["文字・パターン", "表記", "総合判定", "破綻する箇所", "要約"])
    for i, c in enumerate(CHARS):
        v = [c["key"], c["notation"], c["verdict"], c["break_at"] or "—", c["summary"]]
        s.row(v, band=(i % 2 == 1), h=est_height(v, W, 46), center=(1, 3), bold=(1, 3))
    s.blank()
    s.section("2. 特殊文字とは独立に、先に直すべき重大事項")
    s.header(["重要度", "項目", "内容", "対処"], merges=((4, 5),))
    for i, p in enumerate(d["priority_items"]):
        v = [p["severity"], p["title"], p["content"], p["remedy"]]
        s.row(v, band=(i % 2 == 1), h=est_height(v, [22, 26, 28, 122], 60), center=(1,), bold=(1,),
              merges=((4, 5),))

    # ---- 01 データフロー
    W = [8, 30, 46, 86, 46]
    s = Sheet(wb, "01_データフロー", "パスワードが通過する %d のステージ" % len(STAGES), INTRO[2], W)
    s.header(["ID", "ステージ", "該当コード", "値の扱われ方", "着眼点"])
    for i, st in enumerate(STAGES):
        v = [st["id"], st["name"], st["code"], st["handling"], st["focus"]]
        s.row(v, band=(i % 2 == 1), h=est_height(v, W, 50), center=(1,), bold=(1,))

    # ---- 02 マトリクス
    W = [26] + [13] * len(STAGES) + [30]
    s = Sheet(wb, "02_マトリクス", "文字 × ステージ 判定マトリクス", INTRO[3], W)
    s.header(["文字・パターン"] + ["%s\n%s" % (st["id"], st["name"]) for st in STAGES] + ["総合"], h=72)
    vcols = tuple(range(2, 2 + len(STAGES)))
    for i, c in enumerate(CHARS):
        v = [c["key"]] + [d["matrix"][c["key"]][st["id"]] for st in STAGES] + [c["verdict"]]
        s.row(v, band=(i % 2 == 1), h=34, center=(1, len(v)), verdicts=vcols, bold=(1, len(v)), size=10)

    # ---- 03 文字別詳細
    W = [18, 34, 9, 40, 100, 56]
    s = Sheet(wb, "03_文字別詳細", "文字・パターン別／ステージ別 詳細分析",
              "問題が発生しない場合はその理由を、発生する場合は現象・技術的根拠・対処方法を記載する。判定は第 7 章の実測に対応する。", W)
    s.header(["文字・パターン", "ステージ", "判定", "現象", "技術的根拠（なぜそうなるか）", "対処・実装修正"])
    for i, c in enumerate(CHARS):
        if i: s.separator()
        for x in [x for x in d["details"] if x["char"] == c["key"]]:
            v = [x["char"], x["stage"], x["verdict"], x["phenomenon"], x["rationale"], x["remedy"]]
            s.row(v, band=(i % 2 == 1), h=est_height(v, W, 30), center=(1,), verdicts=(3,), bold=(1,))

    # ---- 04 既存欠陥
    W = [8, 10, 30, 44, 60, 54, 60]
    s = Sheet(wb, "04_既存欠陥", "特殊文字とは独立した欠陥一覧",
              "これらは文字種に関わらず常に問題となる。B-20 以降はパラメータストアの登録・取得経路に関するもの。", W)
    s.header(["ID", "重要度", "箇所", "該当コード", "内容", "影響", "対処"])
    sev_fill = {"致命": MID, "重大": MID, "中": GREY, "低": None}
    for i, b in enumerate(d["defects"]):
        v = [b["id"], b["severity"], b["place"], b["code"], b["content"], b["impact"], b["remedy"]]
        s.row(v, band=(i % 2 == 1), h=est_height(v, W, 34), center=(1, 2), mono=(4,), bold=(1, 2))
        c = s.ws.cell(s.r - 1, 2)
        f = sev_fill.get(b["severity"])
        if f: c.fill = fill(f); c.font = Font(name=FONT, size=9, bold=True,
                                              color=(WHITE if f == MID else BLACK))

    # ---- 05 修正コード
    W = [42, 150]
    s = Sheet(wb, "05_修正コード", "修正版コード", INTRO[6].replace("\n\n", "\u3000").replace("\n", " "), W)
    s.ws.row_dimensions[2].height = 52
    s.header(["ファイル", "修正版"])
    for i, f in enumerate(d["fixes"]):
        s.row([f["file"], f["code"]], band=(i % 2 == 1),
              h=min(600, 14 * (f["code"].count("\n") + 2)), mono=(2,))

    # ---- 06 ポリシー
    W = [32, 58, 110]
    s = Sheet(wb, "06_パスワードポリシー", "推奨パスワードポリシー", INTRO[8], W)
    s.header(["区分", "対象", "根拠"])
    for i, p in enumerate(d["policy"]):
        v = [p["category"], p["target"], p["rationale"]]
        s.row(v, band=(i % 2 == 1), h=est_height(v, W, 34), bold=(1,))

    # ---- 07 実測検証ログ
    W = [8, 40, 60, 84, 58]
    s = Sheet(wb, "07_実測検証ログ", "実測検証ログ", INTRO[7], W)
    s.header(["ID", "検証項目", "実行内容", "結果", "意味"])
    for i, e in enumerate(d["experiments"]):
        v = [e["id"], e["title"], e["command"], e["result"], e["meaning"]]
        s.row(v, band=(i % 2 == 1), h=est_height(v, W, 40), center=(1,), mono=(3, 4), bold=(1,))

    # ---- 08 環境固有
    W = [8, 14, 84, 74]
    s = Sheet(wb, "08_実行環境固有事項",
              "実行環境固有の分析 ― EAP 8.1 / UBI 9.8 / OpenJDK 21 / AWS パラメータストア", INTRO[9], W)
    s.section("1. 環境の前提")
    s.header(["構成要素", "バージョン", "本分析に効いてくる性質"], merges=((3, 4),))
    for i, p in enumerate(d["env_premise"]):
        v = [p["component"], p["version"], p["property"]]
        s.row(v, band=(i % 2 == 1), h=est_height(v, [8, 14, 158], 34), merges=((3, 4),))
    s.blank()
    s.section("2. 環境固有の指摘")
    s.header(["ID", "重要度", "内容 / 根拠", "影響と対処"])
    for i, ev in enumerate(d["env_items"]):
        v = [ev["id"], ev["severity"], ev["body"], ev["impact"]]
        s.row(v, band=(i % 2 == 1), h=est_height(v, W, 60), center=(1, 2), bold=(1, 2))
    s.blank()
    s.section("3. コンテナ内での確認コマンド")
    s.row([d["env_commands"]], h=min(700, 14 * (d["env_commands"].count("\n") + 2)), mono=(1,),
          merges=((1, 4),))

    # ---- 09 入力表記ゆれ
    W = [24, 46, 44, 36, 36, 26, 40, 60]
    s = Sheet(wb, "09_入力表記ゆれ対応表", "入力表記ゆれ対応表 ― 何を打つと何が保存され、何が起動時に届くか",
              d["notation_note"].replace("\n", "\u3000"), W)
    s.ws.row_dimensions[2].height = 60
    s.header(["入力した表記", "登録経路", "保存される値 (hex)", "推奨経路で届く値 (hex)",
              "現行経路で届く値 (hex)", "JCEKS", "現行 S5 の結果", "総合判定"], h=42)
    for i, r in enumerate(d["notation_table"]):
        v = [r["typed"], r["route"], r["stored"], r["env_recommended"], r["env_current"],
             r["jceks"], r["s5"], r["verdict"]]
        s.row(v, band=(i % 2 == 1), h=est_height(v, W, 34), mono=(1, 3, 4, 5), center=(6,))
        c = s.ws.cell(s.r - 1, 6)
        if c.value and c.value.startswith("NG"):
            c.fill = fill(MID); c.font = Font(name=FONT, size=9, bold=True, color=WHITE)
    wb.save(path)

def main():
    md_path = os.path.join(ROOT, BASENAME + ".md")
    xl_path = os.path.join(ROOT, BASENAME + ".xlsx")
    open(md_path, "w", encoding="utf-8").write(build_md())
    build_xlsx(xl_path)
    print("wrote %s" % md_path)
    print("wrote %s" % xl_path)
    print("  文字・パターン %d / ステージ %d / 詳細 %d / 欠陥 %d / 実測 %d"
          % (len(CHARS), len(STAGES), len(d["details"]), len(d["defects"]), len(d["experiments"])))

if __name__ == "__main__":
    main()
