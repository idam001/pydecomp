"""pydecomp - quality."""
from __future__ import annotations

import re
import warnings

from ..bytecode.lifter import LEFTOVER_MARK, fix_empty_blocks
from ..terminal.banner import header

def ensure_parseable(lines: list) -> list:
    """Repair the lifted text until ``compile()`` accepts it.

    Two different failures need two different repairs: a missing body gets a
    ``pass`` (the block structure is right, the statements were dropped), while
    a line the lifter could not line up is kept as a comment so the rest of the
    module still compiles.
    """
    lines = [("# " + line) if LEFTOVER_MARK.match(line) else line for line in lines]
    lines = fix_empty_blocks(lines)
    text = "\n".join(lines)
    for _ in range(4000):
        try:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always", SyntaxWarning)
                compile(text, "<lifted>", "exec")
            if not caught:
                return lines
            changed = False
            for warning in caught:
                idx = (getattr(warning, "lineno", 0) or 0) - 1
                if not 0 <= idx < len(lines):
                    continue
                line = lines[idx]
                for old, new in ((" is not ", " != "), (" is ", " == ")):
                    if old in line:
                        lines[idx] = line.replace(old, new, 1)
                        changed = True
                        break
                else:
                    lines[idx] = "# " + line.strip()
                    changed = True
                if changed:
                    break
            text = "\n".join(lines)
            if not changed:
                return lines
        except SyntaxError as exc:
            message = exc.msg or ""
            lineno = (exc.lineno or 0) - 1
            if not 0 <= lineno < len(lines):
                return lines
            line = lines[lineno]
            body = line.lstrip(" ")
            indent = line[:len(line) - len(body)]
            if "expected an indented block" in message:
                # the reported line is where the parser noticed, not the header
                header = re.search(r"on line (\d+)", message)
                target = int(header.group(1)) - 1 if header else lineno
                if not 0 <= target < len(lines):
                    target = lineno
                head = lines[target]
                head_body = head.lstrip(" ")
                head_indent = head[:len(head) - len(head_body)]
                lines.insert(target + 1, head_indent + "    pass")
            elif body.startswith("#") or not body.strip():
                lines.insert(lineno + 1, indent + "pass")
            elif body.rstrip().endswith(":"):
                lines[lineno:lineno + 1] = [f"{indent}# {body}", f"{indent}    pass"]
            else:
                lines[lineno] = f"{indent}# {body}"
            text = "\n".join(lines)
        except (ValueError, RecursionError, MemoryError):
            return lines
    return lines
