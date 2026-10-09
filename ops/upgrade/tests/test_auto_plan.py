"""Planner regression tests: isolated Git repositories, no Docker or deployment."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]


class AutoPlanTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        for name in ('ops/upgrade/build-upgrade-pack.sh', 'ops/upgrade/build-patch.sh',
                     'ops/lib/common.sh', 'ops/lib/signing.sh'):
            dest = self.repo / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, dest)
        self.write('VERSION.md', '当前已发布版本：`1.2.0`\n')
        self.write('server/app.go', 'baseline\n')
        self.write('server/migrations/000001_init.up.sql', 'SELECT 1;')
        self.git('init', '-q')
        self.git('config', 'user.email', 'test@example.invalid')
        self.git('config', 'user.name', 'test')
        self.commit()
        self.git('tag', 'wdsp-v1.2.0')

    def write(self, name, content):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.repo), *args], stderr=subprocess.STDOUT)

    def commit(self):
        self.git('add', '-A')
        self.git('commit', '-qm', 'fixture')

    def plan(self, *args, ok=True):
        env = dict(os.environ)
        env.pop('WDSP_SIGNING_KEY', None)
        result = subprocess.run(['bash', str(self.repo / 'ops/upgrade/build-upgrade-pack.sh'),
                                 '--to', '1.3.0', '--plan', *args], env=env,
                                capture_output=True, text=True)
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode == 0, ok, output)
        return output

    def test_default_auto_and_from(self):
        self.write('web/src/app.ts', 'new')
        output = self.plan()
        self.assertIn('auto 识别组件: web', output)
        self.assertIn('wdsp-v1.2.0', output)
        self.assertFalse((self.repo / 'dist').exists())

    def test_shared_dependency(self):
        self.write('gateway/dynamic_security/policy.go', 'new')
        output = self.plan()
        self.assertIn('auto 识别组件: api gateway', output)

    def test_shared_module_metadata(self):
        self.write('gateway/dynamic_security/go.mod', 'module example')
        self.assertIn('auto 识别组件: api gateway netmgrd', self.plan())

    def test_rename_counts_source_and_destination(self):
        (self.repo / 'web').mkdir()
        self.git('mv', 'server/app.go', 'web/app.go')
        self.assertIn('auto 识别组件: api web', self.plan())
        self.commit()
        self.assertIn('auto 识别组件: api web', self.plan())

    def test_newline_filename(self):
        self.write('web/src/a\nodd.ts', 'new')
        self.assertIn('auto 识别组件: web', self.plan())

    def test_unknown_path(self):
        self.write('unknown-runtime/new.conf', 'new')
        self.assertIn('未命中组件映射', self.plan(ok=False))

    def test_host_change_fails_closed(self):
        self.write('deployment/docker-compose.stage5.yml', 'changed')
        self.write('server/app.go', 'changed')
        self.assertIn('宿主机', self.plan(ok=False))

    def test_no_changes(self):
        self.plan(ok=False)

    def test_missing_tag(self):
        self.git('tag', '-d', 'wdsp-v1.2.0')
        self.assertIn('git fetch --tags', self.plan(ok=False))

    def test_versions(self):
        self.write('web/app.ts', 'new')
        self.assertIn('bugfix', self.plan('--to', '1.2.1'))
        self.plan('--to', '2.0.0', ok=False)
        self.plan('--to', '01.3.0', ok=False)

    def test_old_entry_forwards_to_auto(self):
        self.write('web/app.ts', 'new')
        result = subprocess.run(['bash', str(self.repo / 'ops/upgrade/build-patch.sh'),
                                 '--to', '1.3.0', '--plan'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('auto 识别组件: web', result.stdout)

    def test_tag_must_be_ancestor(self):
        self.write('web/app.ts', 'new')
        self.commit()
        self.git('tag', '-f', 'wdsp-v1.2.0')
        self.git('checkout', '--detach', 'HEAD~1')
        self.assertIn('不是当前 HEAD 的祖先', self.plan(ok=False))


if __name__ == '__main__':
    unittest.main()
