"""依赖核查回归（NG-REL-02 批次 C 实证 F1）：upgrade-executor.sh / install-executor.sh
的依赖清单必须包含 diff/cmp（diffutils），缺失时报准确错误（点名 diffutils），
而不是在下游比对处报「存在未声明文件」等误导文案。

做法：从脚本源码抽取依赖核查循环（唯一的 `for cmd in ... done` 块），在仅含
 stub 命令的 PATH 下执行，不触碰 Docker/systemd/系统状态。
"""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPTS = [
    Path(__file__).resolve().parents[1] / "upgrade-executor.sh",
    Path(__file__).resolve().parents[1] / "install-executor.sh",
]


def extract_dep_block(source: str) -> tuple[list[str], str]:
    """返回（命令清单, 依赖核查块源码）。每个脚本恰有一个 for cmd in 循环。"""
    start = source.index("for cmd in ")
    end = source.index("done", start) + len("done")
    block = source[start:end]
    header = block.splitlines()[0]
    cmds = header[len("for cmd in "):].rsplit("; do", 1)[0].split()
    return cmds, block


def run_block(block: str, present: list[str], workdir: str) -> subprocess.CompletedProcess:
    stub = Path(workdir) / "bin"
    stub.mkdir()
    for name in present:
        os.symlink("/usr/bin/true", stub / name)
    env = {"PATH": str(stub)}
    return subprocess.run(["/bin/bash", "-c", block], env=env, capture_output=True, text=True)


class TestExecutorDependencyCheck(unittest.TestCase):
    def test_diffutils_commands_required(self):
        for script in SCRIPTS:
            with self.subTest(script=script.name):
                cmds, block = extract_dep_block(script.read_text())
                self.assertIn("diff", cmds, f"{script.name} 依赖清单缺 diff")
                self.assertIn("cmp", cmds, f"{script.name} 依赖清单缺 cmp")

    def test_all_present_passes(self):
        for script in SCRIPTS:
            with self.subTest(script=script.name):
                cmds, block = extract_dep_block(script.read_text())
                with tempfile.TemporaryDirectory() as td:
                    r = run_block(block, cmds, td)
                self.assertEqual(r.returncode, 0, r.stderr)

    def test_missing_diff_names_diffutils(self):
        for script in SCRIPTS:
            with self.subTest(script=script.name):
                cmds, block = extract_dep_block(script.read_text())
                with tempfile.TemporaryDirectory() as td:
                    r = run_block(block, [c for c in cmds if c != "diff"], td)
                self.assertEqual(r.returncode, 1)
                self.assertIn("缺少命令: diff", r.stderr)
                self.assertIn("diffutils", r.stderr)

    def test_missing_cmp_names_diffutils(self):
        for script in SCRIPTS:
            with self.subTest(script=script.name):
                cmds, block = extract_dep_block(script.read_text())
                with tempfile.TemporaryDirectory() as td:
                    r = run_block(block, [c for c in cmds if c != "cmp"], td)
                self.assertEqual(r.returncode, 1)
                self.assertIn("缺少命令: cmp", r.stderr)
                self.assertIn("diffutils", r.stderr)

    def test_missing_other_command_keeps_plain_message(self):
        for script in SCRIPTS:
            with self.subTest(script=script.name):
                cmds, block = extract_dep_block(script.read_text())
                with tempfile.TemporaryDirectory() as td:
                    r = run_block(block, [c for c in cmds if c != "jq"], td)
                self.assertEqual(r.returncode, 1)
                self.assertIn("缺少命令: jq", r.stderr)
                self.assertNotIn("diffutils", r.stderr)


if __name__ == "__main__":
    unittest.main()
