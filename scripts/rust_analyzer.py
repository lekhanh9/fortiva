#!/usr/bin/env python3
"""
main.py — Công cụ phân tích cú pháp hàng loạt file Rust (.rs)

Chỉ dùng thư viện chuẩn của Python (không cần pip install gì thêm).

Cách dùng:
    python3 main.py <đường_dẫn> [đường_dẫn ...] [tùy chọn]

Ví dụ:
    python3 main.py ./src                     # quét cả thư mục (đệ quy)
    python3 main.py a.rs b.rs                  # quét từng file cụ thể
    python3 main.py ./src --json report.json   # xuất báo cáo JSON
    python3 main.py ./src --verbose            # in chi tiết từng file
    python3 main.py ./src --workers 8          # chạy song song 8 luồng

Ghi chú: Đây là một trình phân tích "hạng nhẹ" dựa trên quét ký tự + regex,
không phải trình biên dịch Rust thật, nhưng đủ chính xác cho hầu hết mã
nguồn thực tế để thống kê cấu trúc và phát hiện lỗi cú pháp cơ bản
(ngoặc/dấu nháy không khớp).
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import dataclasses
import json
import re
import sys
from pathlib import Path
from typing import Iterable


# --------------------------------------------------------------------------
# 1. Bóc tách comment & string literal để tránh regex "ăn nhầm" nội dung
#    nằm trong chuỗi hoặc comment.
# --------------------------------------------------------------------------

def strip_comments_and_strings(src: str) -> tuple[str, list[str]]:
    """
    Trả về (mã_nguồn_đã_làm_sạch, danh_sách_lỗi).
    Mọi comment và nội dung bên trong string/char literal được thay bằng
    khoảng trắng (giữ nguyên số dòng và vị trí dấu ngoặc để việc đếm
    ngoặc và số dòng vẫn chính xác).
    """
    out = []
    errors: list[str] = []
    i = 0
    n = len(src)
    line = 1

    def push(ch: str):
        nonlocal line
        out.append(ch)
        if ch == "\n":
            line += 1

    while i < n:
        c = src[i]

        # comment dòng //
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                i += 1
            continue

        # comment khối /* ... */ (hỗ trợ lồng nhau)
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            depth = 1
            start_line = line
            i += 2
            while i < n and depth > 0:
                if src[i] == "/" and i + 1 < n and src[i + 1] == "*":
                    depth += 1
                    i += 2
                elif src[i] == "*" and i + 1 < n and src[i + 1] == "/":
                    depth -= 1
                    i += 2
                else:
                    if src[i] == "\n":
                        push("\n")
                    i += 1
            if depth != 0:
                errors.append(f"Dòng {start_line}: comment khối /* */ không đóng")
            continue

        # raw string: r"...", r#"..."#, r##"..."##, ... (có thể có tiền tố b)
        m = re.match(r'(b?r)(#*)"', src[i:])
        if m:
            prefix, hashes = m.group(1), m.group(2)
            start_line = line
            i += len(prefix) + len(hashes) + 1
            closing = '"' + hashes
            end = src.find(closing, i)
            if end == -1:
                errors.append(f"Dòng {start_line}: raw string không đóng")
                for ch in src[i:]:
                    push(ch if ch == "\n" else " ")
                i = n
                continue
            for ch in src[i:end]:
                push(ch if ch == "\n" else " ")
            i = end + len(closing)
            push('"')
            continue

        # string thường "...", có thể có tiền tố b
        if c == '"' or (c == "b" and i + 1 < n and src[i + 1] == '"'):
            start_line = line
            i += 1 if c == '"' else 2
            closed = False
            while i < n:
                if src[i] == "\\" and i + 1 < n:
                    i += 2
                    continue
                if src[i] == '"':
                    i += 1
                    closed = True
                    break
                if src[i] == "\n":
                    push("\n")
                i += 1
            if not closed:
                errors.append(f"Dòng {start_line}: string literal không đóng")
            push('"')
            continue

        # char literal 'x' — phân biệt với lifetime 'a bằng cách thử khớp
        # mẫu char literal hợp lệ trước (escape hoặc 1 ký tự) rồi mới coi
        # là lifetime nếu không khớp.
        if c == "'":
            m2 = re.match(r"'(\\.|[^'\\])'", src[i:])
            if m2:
                push("'x'")
                i += len(m2.group(0))
                continue
            # coi như lifetime ('a, 'static, ...) — giữ nguyên để không
            # phá vỡ cấu trúc, không tính là string
            push(c)
            i += 1
            continue

        push(c)
        i += 1

    return "".join(out), errors


# --------------------------------------------------------------------------
# 2. Kiểm tra ngoặc cân bằng trên mã nguồn đã làm sạch
# --------------------------------------------------------------------------

PAIRS = {")": "(", "]": "[", "}": "{"}
OPENERS = set(PAIRS.values())


def check_balanced_delimiters(clean_src: str) -> list[str]:
    stack: list[tuple[str, int]] = []
    errors = []
    line = 1
    for ch in clean_src:
        if ch == "\n":
            line += 1
        elif ch in OPENERS:
            stack.append((ch, line))
        elif ch in PAIRS:
            if not stack:
                errors.append(f"Dòng {line}: thừa dấu đóng '{ch}'")
                continue
            top_ch, _ = stack.pop()
            if top_ch != PAIRS[ch]:
                errors.append(
                    f"Dòng {line}: dấu đóng '{ch}' không khớp với '{top_ch}' đang mở"
                )
    for ch, ln in stack:
        errors.append(f"Dòng {ln}: dấu mở '{ch}' không được đóng")
    return errors


# --------------------------------------------------------------------------
# 3. Trích xuất các thành phần cú pháp bằng regex trên mã nguồn đã làm sạch
# --------------------------------------------------------------------------

ITEM_PATTERNS = {
    "functions": re.compile(r"\bfn\s+([A-Za-z_]\w*)"),
    "structs": re.compile(r"\bstruct\s+([A-Za-z_]\w*)"),
    "enums": re.compile(r"\benum\s+([A-Za-z_]\w*)"),
    "traits": re.compile(r"\btrait\s+([A-Za-z_]\w*)"),
    "impls": re.compile(r"\bimpl\b"),
    "modules": re.compile(r"\bmod\s+([A-Za-z_]\w*)"),
    "uses": re.compile(r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?use\s+[^;]+;"),
    "macro_defs": re.compile(r"\bmacro_rules!\s*([A-Za-z_]\w*)"),
    "derives": re.compile(r"#\[derive\("),
    "unsafe_blocks": re.compile(r"\bunsafe\s*\{"),
    "tests": re.compile(r"#\[test\]"),
    "pub_items": re.compile(r"\bpub(?:\([^)]*\))?\s+(?:fn|struct|enum|trait|mod|const|static)\b"),
    "todo_fixme": re.compile(r"\b(TODO|FIXME|XXX)\b"),
}


@dataclasses.dataclass
class FileReport:
    path: str
    total_lines: int = 0
    blank_lines: int = 0
    comment_lines: int = 0
    code_lines: int = 0
    counts: dict = dataclasses.field(default_factory=dict)
    errors: list = dataclasses.field(default_factory=list)

    @property
    def ok(self) -> bool:
        return len(self.errors) == 0


def count_line_kinds(original_src: str, clean_src: str) -> tuple[int, int, int, int]:
    orig_lines = original_src.splitlines()
    clean_lines = clean_src.splitlines()
    total = len(orig_lines)
    blank = 0
    comment_only = 0
    code = 0
    for orig, clean in zip(orig_lines, clean_lines):
        stripped_orig = orig.strip()
        stripped_clean = clean.strip()
        if stripped_orig == "":
            blank += 1
        elif stripped_clean == "":
            # dòng gốc có nội dung nhưng sau khi bóc comment/string thì rỗng
            comment_only += 1
        else:
            code += 1
    return total, blank, comment_only, code


def analyze_file(path: Path) -> FileReport:
    report = FileReport(path=str(path))
    try:
        original = path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:  # noqa: BLE001
        report.errors.append(f"Không đọc được file: {e}")
        return report

    clean, strip_errors = strip_comments_and_strings(original)
    report.errors.extend(strip_errors)
    report.errors.extend(check_balanced_delimiters(clean))

    total, blank, comment_only, code = count_line_kinds(original, clean)
    report.total_lines = total
    report.blank_lines = blank
    report.comment_lines = comment_only
    report.code_lines = code

    for name, pattern in ITEM_PATTERNS.items():
        # TODO/FIXME thường nằm trong comment, nên quét trên mã GỐC;
        # các mục còn lại quét trên mã đã làm sạch để tránh nhận nhầm
        # nội dung bên trong string/comment.
        haystack = original if name == "todo_fixme" else clean
        report.counts[name] = len(pattern.findall(haystack))

    return report


# --------------------------------------------------------------------------
# 4. Thu thập file & chạy song song
# --------------------------------------------------------------------------

def collect_rust_files(paths: Iterable[str]) -> list[Path]:
    files: list[Path] = []
    for p_str in paths:
        p = Path(p_str)
        if p.is_dir():
            files.extend(sorted(p.rglob("*.rs")))
        elif p.is_file() and p.suffix == ".rs":
            files.append(p)
        elif p.is_file():
            print(f"Cảnh báo: bỏ qua '{p}' vì không phải file .rs", file=sys.stderr)
        else:
            print(f"Cảnh báo: đường dẫn không tồn tại '{p}'", file=sys.stderr)
    # loại trùng, giữ thứ tự
    seen = set()
    unique = []
    for f in files:
        rf = f.resolve()
        if rf not in seen:
            seen.add(rf)
            unique.append(f)
    return unique


def run_analysis(files: list[Path], workers: int) -> list[FileReport]:
    if not files:
        return []
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        return list(ex.map(analyze_file, files))


# --------------------------------------------------------------------------
# 5. In báo cáo
# --------------------------------------------------------------------------

ITEM_LABELS = {
    "functions": "Hàm (fn)",
    "structs": "Struct",
    "enums": "Enum",
    "traits": "Trait",
    "impls": "Khối impl",
    "modules": "Module (mod)",
    "uses": "Câu lệnh use",
    "macro_defs": "macro_rules!",
    "derives": "#[derive(...)]",
    "unsafe_blocks": "Khối unsafe",
    "tests": "#[test]",
    "pub_items": "Item pub",
    "todo_fixme": "TODO/FIXME",
}


def print_report(reports: list[FileReport], verbose: bool) -> None:
    if not reports:
        print("Không tìm thấy file .rs nào để phân tích.")
        return

    if verbose:
        for r in reports:
            status = "OK" if r.ok else f"{len(r.errors)} LỖI"
            print(f"\n=== {r.path} [{status}] ===")
            print(
                f"  Dòng: {r.total_lines} tổng | {r.code_lines} code | "
                f"{r.comment_lines} comment | {r.blank_lines} trống"
            )
            for name, label in ITEM_LABELS.items():
                c = r.counts.get(name, 0)
                if c:
                    print(f"  {label}: {c}")
            for err in r.errors:
                print(f"  LỖI CÚ PHÁP: {err}")

    total_files = len(reports)
    files_with_errors = [r for r in reports if not r.ok]
    total_lines = sum(r.total_lines for r in reports)
    total_code = sum(r.code_lines for r in reports)
    total_comment = sum(r.comment_lines for r in reports)
    total_blank = sum(r.blank_lines for r in reports)

    agg = {name: 0 for name in ITEM_LABELS}
    for r in reports:
        for name in ITEM_LABELS:
            agg[name] += r.counts.get(name, 0)

    print("\n" + "=" * 60)
    print("TỔNG QUAN")
    print("=" * 60)
    print(f"Số file đã quét      : {total_files}")
    print(f"File có lỗi cú pháp  : {len(files_with_errors)}")
    print(f"Tổng số dòng         : {total_lines}")
    print(f"  - dòng code        : {total_code}")
    print(f"  - dòng comment     : {total_comment}")
    print(f"  - dòng trống       : {total_blank}")
    print("-" * 60)
    for name, label in ITEM_LABELS.items():
        print(f"{label:<20}: {agg[name]}")

    if files_with_errors:
        print("-" * 60)
        print(f"Các file có lỗi cú pháp ({len(files_with_errors)}):")
        for r in files_with_errors:
            print(f"  - {r.path} ({len(r.errors)} lỗi)")
            if not verbose:
                for err in r.errors[:3]:
                    print(f"      {err}")
                if len(r.errors) > 3:
                    print(f"      ... và {len(r.errors) - 3} lỗi khác")
    print("=" * 60)


def build_json_report(reports: list[FileReport]) -> dict:
    return {
        "summary": {
            "total_files": len(reports),
            "files_with_errors": sum(1 for r in reports if not r.ok),
            "total_lines": sum(r.total_lines for r in reports),
            "code_lines": sum(r.code_lines for r in reports),
            "comment_lines": sum(r.comment_lines for r in reports),
            "blank_lines": sum(r.blank_lines for r in reports),
            "counts": {
                name: sum(r.counts.get(name, 0) for r in reports)
                for name in ITEM_LABELS
            },
        },
        "files": [dataclasses.asdict(r) for r in reports],
    }


# --------------------------------------------------------------------------
# 6. CLI
# --------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Phân tích cú pháp hàng loạt file Rust (.rs)."
    )
    parser.add_argument(
        "paths", nargs="+", help="Thư mục hoặc file .rs cần phân tích"
    )
    parser.add_argument(
        "--json", metavar="FILE", help="Xuất báo cáo dạng JSON ra FILE"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="In chi tiết từng file"
    )
    parser.add_argument(
        "--workers", type=int, default=8, help="Số luồng chạy song song (mặc định 8)"
    )
    parser.add_argument(
        "--fail-on-error",
        action="store_true",
        help="Thoát với mã lỗi khác 0 nếu có file lỗi cú pháp",
    )
    args = parser.parse_args()

    files = collect_rust_files(args.paths)
    reports = run_analysis(files, args.workers)

    print_report(reports, args.verbose)

    if args.json:
        data = build_json_report(reports)
        Path(args.json).write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(f"\nĐã ghi báo cáo JSON vào: {args.json}")

    if args.fail_on_error and any(not r.ok for r in reports):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
