#!/usr/bin/env python3
"""将管理员手册 Markdown 源转换为 docx（软著版式）。

用法：python build_docx.py <manual.md> <out.docx> <产品全名>

支持的语法：
  # 首个 H1        → 封面标题（居中大字）
  **...** 开头三行  → 封面副信息（居中）
  # 第N章 / ## x.y → 标题1/标题2/标题3
  ---             → 分页
  | a | b |       → 表格（Table Grid）
  - item          → 项目符号
  1. item         → 编号列表
  [[SHOT:图题|指引]] → 截图占位框 + 图题 + 灰色指引
  > text          → 说明性段落（楷体）
  **bold** 行内    → 加粗 run
"""
import re
import sys

from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor

BODY_FONT = '宋体'
HEAD_FONT = '黑体'
ASCII_FONT = 'Times New Roman'


def set_font(run, name_east=BODY_FONT, size=12, bold=False, color=None, italic=False):
    run.font.name = ASCII_FONT
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.italic = italic
    if color:
        run.font.color.rgb = color
    rpr = run._element.get_or_add_rPr()
    rfonts = rpr.find(qn('w:rFonts'))
    if rfonts is None:
        rfonts = OxmlElement('w:rFonts')
        rpr.append(rfonts)
    rfonts.set(qn('w:eastAsia'), name_east)


def add_runs(p, text, size=12, base_bold=False):
    """按 **bold** 切分添加 run。"""
    for i, seg in enumerate(re.split(r'\*\*', text)):
        if not seg:
            continue
        set_font(p.add_run(seg), BODY_FONT, size, bold=base_bold or i % 2 == 1)


def add_page_break(doc):
    doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)


def set_cell_text(cell, text, bold=False):
    cell.text = ''
    p = cell.paragraphs[0]
    add_runs(p, text, size=10.5, base_bold=bold)


def add_toc(doc):
    """插入 Word 目录域（打开文档后按 F9 或右键更新）。"""
    p = doc.add_paragraph()
    run = p.add_run()
    fld_begin = OxmlElement('w:fldChar')
    fld_begin.set(qn('w:fldCharType'), 'begin')
    instr = OxmlElement('w:instrText')
    instr.set(qn('xml:space'), 'preserve')
    instr.text = 'TOC \\o "1-2" \\h \\z \\u'
    fld_sep = OxmlElement('w:fldChar')
    fld_sep.set(qn('w:fldCharType'), 'separate')
    t = OxmlElement('w:t')
    t.text = '（目录内容：请在 Word 中右键此处选择“更新域”生成）'
    fld_end = OxmlElement('w:fldChar')
    fld_end.set(qn('w:fldCharType'), 'end')
    for el in (fld_begin, instr, fld_sep, t, fld_end):
        run._element.append(el)


def add_shot_box(doc, caption, hint):
    """截图占位：带边框的空表格 + 居中图题 + 灰色指引。"""
    table = doc.add_table(rows=1, cols=1)
    table.style = 'Table Grid'
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    row = table.rows[0]
    row.height = Cm(7.5)
    tr_pr = row._tr.get_or_add_trPr()
    tr_height = OxmlElement('w:trHeight')
    tr_height.set(qn('w:val'), str(int(7.5 * 567)))
    tr_height.set(qn('w:hRule'), 'atLeast')
    tr_pr.append(tr_height)
    cell = row.cells[0]
    cell.text = ''
    p = cell.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    set_font(p.add_run('（此处插入截图）'), BODY_FONT, 12, color=RGBColor(0x99, 0x99, 0x99))
    cap = doc.add_paragraph()
    cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
    set_font(cap.add_run(caption), HEAD_FONT, 10.5, bold=True)
    hp = doc.add_paragraph()
    hp.alignment = WD_ALIGN_PARAGRAPH.CENTER
    set_font(hp.add_run('截图指引：' + hint), BODY_FONT, 9, italic=True, color=RGBColor(0x88, 0x88, 0x88))
    doc.add_paragraph()


def setup_styles(doc):
    normal = doc.styles['Normal']
    normal.font.name = ASCII_FONT
    normal.font.size = Pt(12)
    normal.element.rPr.rFonts.set(qn('w:eastAsia'), BODY_FONT)
    for i, (size, before, after) in enumerate([(18, 12, 12), (15, 10, 8), (13, 8, 6)], start=1):
        st = doc.styles[f'Heading {i}']
        st.font.name = ASCII_FONT
        st.font.size = Pt(size)
        st.font.bold = True
        st.font.color.rgb = RGBColor(0, 0, 0)
        st.element.rPr.rFonts.set(qn('w:eastAsia'), HEAD_FONT)
        st.paragraph_format.space_before = Pt(before)
        st.paragraph_format.space_after = Pt(after)


def setup_page(doc, product):
    sec = doc.sections[0]
    sec.page_width, sec.page_height = Cm(21.0), Cm(29.7)
    sec.left_margin = sec.right_margin = Cm(2.6)
    sec.top_margin = sec.bottom_margin = Cm(2.8)
    hp = sec.header.paragraphs[0]
    hp.alignment = WD_ALIGN_PARAGRAPH.CENTER
    set_font(hp.add_run(f'{product} 管理员手册'), BODY_FONT, 9, color=RGBColor(0x66, 0x66, 0x66))
    fp = sec.footer.paragraphs[0]
    fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = fp.add_run()
    for kind, val in (('begin', None), (None, 'PAGE'), ('end', None)):
        if kind:
            fld = OxmlElement('w:fldChar')
            fld.set(qn('w:fldCharType'), kind)
            run._element.append(fld)
        else:
            instr = OxmlElement('w:instrText')
            instr.text = val
            run._element.append(instr)
    set_font(run, BODY_FONT, 9)


def flush_table(doc, rows):
    if not rows:
        return
    ncol = max(len(r) for r in rows)
    table = doc.add_table(rows=len(rows), cols=ncol)
    table.style = 'Table Grid'
    for ri, row in enumerate(rows):
        for ci in range(ncol):
            set_cell_text(table.rows[ri].cells[ci], row[ci] if ci < len(row) else '', bold=(ri == 0))
    doc.add_paragraph()


def convert(md_path, out_path, product):
    doc = Document()
    setup_styles(doc)
    setup_page(doc, product)

    lines = open(md_path, encoding='utf-8').read().split('\n')
    i = 0
    cover_done = False
    toc_done = False
    table_rows = []

    def is_table_line(s):
        return s.strip().startswith('|') and s.strip().endswith('|')

    while i < len(lines):
        line = lines[i]
        s = line.strip()

        if is_table_line(s):
            cells = [c.strip() for c in s.strip('|').split('|')]
            if not all(re.fullmatch(r':?-{2,}:?', c) for c in cells):
                table_rows.append(cells)
            i += 1
            continue
        if table_rows:
            flush_table(doc, table_rows)
            table_rows = []

        if not s:
            i += 1
            continue

        if s.startswith('# ') and not cover_done:
            p = doc.add_paragraph()
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.space_before = Pt(150)
            set_font(p.add_run(s[2:].strip()), HEAD_FONT, 26, bold=True)
            cover_done = True
            i += 1
            continue

        if cover_done and not toc_done and s.startswith('**') and s.endswith('**'):
            p = doc.add_paragraph()
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.space_before = Pt(18)
            set_font(p.add_run(s.strip('*').strip()), BODY_FONT, 14)
            i += 1
            continue

        if s.startswith('> ') and not toc_done:
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(60)
            set_font(p.add_run(s[2:].strip()), BODY_FONT, 9, italic=True, color=RGBColor(0x88, 0x88, 0x88))
            i += 1
            continue

        if s == '---':
            if cover_done and not toc_done:
                add_page_break(doc)
                p = doc.add_paragraph()
                p.alignment = WD_ALIGN_PARAGRAPH.CENTER
                set_font(p.add_run('目  录'), HEAD_FONT, 18, bold=True)
                add_toc(doc)
                toc_done = True
            add_page_break(doc)
            i += 1
            continue

        m = re.fullmatch(r'\[\[SHOT:(.*?)\|(.*)\]\]', s)
        if m:
            add_shot_box(doc, m.group(1).strip(), m.group(2).strip())
            i += 1
            continue

        if s.startswith('### '):
            doc.add_heading(s[4:].strip(), level=3)
        elif s.startswith('## '):
            doc.add_heading(s[3:].strip(), level=2)
        elif s.startswith('# '):
            doc.add_heading(s[2:].strip(), level=1)
        elif re.match(r'^\d+\.\s', s):
            p = doc.add_paragraph(style='List Number')
            add_runs(p, re.sub(r'^\d+\.\s', '', s))
        elif s.startswith('- '):
            p = doc.add_paragraph(style='List Bullet')
            add_runs(p, s[2:].strip())
        elif s.startswith('> '):
            p = doc.add_paragraph()
            add_runs(p, s[2:].strip(), size=10.5)
        else:
            p = doc.add_paragraph()
            p.paragraph_format.first_line_indent = Pt(24)
            add_runs(p, s)
        i += 1

    if table_rows:
        flush_table(doc, table_rows)
    doc.save(out_path)
    print('saved:', out_path)


if __name__ == '__main__':
    convert(sys.argv[1], sys.argv[2], sys.argv[3])
