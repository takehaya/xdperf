"""Exercise the scenario runner without network privileges or xdperf."""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


class RunnerChecks(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        source = Path(__file__).resolve().parents[2] / 'run_all.sh'
        shutil.copyfile(source, self.root / 'run_all.sh')
        (self.root / 'common').mkdir()
        (self.root / 'common/test_utils.sh').write_text('''check_root() { :; }
print_info() { echo "$1"; }
print_success() { echo "$1"; }
print_error() { echo "$1"; }
''')
        self.scenario = self.root / 'scenario'
        self.scenario.mkdir()
        (self.scenario / 'README.md').touch()
        for step in ('setup', 'test', 'teardown'):
            self.step(step, 0)

    def step(self, name, status):
        script = self.scenario / (name + '.sh')
        script.write_text(f'#!/bin/bash\necho {name} >> "{self.root}/steps"\nexit {status}\n')
        script.chmod(0o755)

    def run_scenario(self):
        result = subprocess.run(['bash', str(self.root / 'run_all.sh')],
                                capture_output=True, text=True, timeout=10)
        steps = self.root / 'steps'
        return result, steps.read_text().splitlines() if steps.exists() else []

    def test_pass(self):
        result, steps = self.run_scenario()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(steps, ['setup', 'test', 'teardown'])
        self.assertIn('Passed: 1', result.stdout)

    def test_setup_failure_still_cleans_up(self):
        self.step('setup', 1)
        result, steps = self.run_scenario()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(steps, ['setup', 'teardown'])

    def test_test_failure_still_cleans_up(self):
        self.step('test', 1)
        result, steps = self.run_scenario()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(steps, ['setup', 'test', 'teardown'])

    def test_skip_and_teardown_failure(self):
        self.step('test', 3)
        result, steps = self.run_scenario()
        self.assertEqual(result.returncode, 0)
        self.assertIn('Skipped: 1', result.stdout)
        self.assertEqual(steps, ['setup', 'test', 'teardown'])
        self.step('teardown', 1)
        result, _ = self.run_scenario()
        self.assertEqual(result.returncode, 1)
        self.assertIn('Teardown failed', result.stdout)

    def test_interrupt_still_cleans_up(self):
        for step in ('setup', 'test'):
            for signal, expected in [('INT', 130), ('TERM', 143)]:
                with self.subTest(step=step, signal=signal):
                    for name in ('setup', 'test', 'teardown'):
                        self.step(name, 0)
                    (self.root / 'steps').unlink(missing_ok=True)
                    script = self.scenario / (step + '.sh')
                    script.write_text(f'#!/bin/bash\necho {step} >> "{self.root}/steps"\nkill -{signal} "$PPID"\n')
                    result, steps = self.run_scenario()
                    self.assertEqual(result.returncode, expected, result.stdout)
                    self.assertEqual(steps, (['setup'] if step == 'setup' else ['setup', 'test']) + ['teardown'])

    def test_missing_entrypoint_fails_before_setup(self):
        (self.scenario / 'teardown.sh').unlink()
        result, steps = self.run_scenario()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(steps, [])
        self.assertIn('Missing scenario entrypoint', result.stdout)


if __name__ == '__main__':
    unittest.main()
