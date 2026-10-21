"""Exercise the scenario runner without network privileges or xdperf."""
import os
import shutil
import signal
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

    def test_term_stops_running_descendants_before_teardown(self):
        script = self.scenario / 'test.sh'
        script.write_text(f'''#!/bin/bash
echo test >> "{self.root}/steps"
timeout --foreground 60 sleep 60 &
child=$!
echo "$$" > "{self.root}/step.pid"
echo "$child" > "{self.root}/child.pid"
trap 'wait "$child" || true; exit 0' TERM
kill -TERM "$PPID"
wait "$child"
''')
        (self.scenario / 'teardown.sh').write_text(f'''#!/bin/bash
if kill -0 "$(cat "{self.root}/child.pid")" 2>/dev/null; then
    touch "{self.root}/cleanup-with-child"
fi
echo teardown >> "{self.root}/steps"
''')
        with (self.root / 'output').open('w') as output:
            process = subprocess.Popen(['bash', str(self.root / 'run_all.sh')],
                                       stdout=output, stderr=subprocess.STDOUT)
            try:
                self.assertEqual(process.wait(timeout=10), 143)
                self.assertEqual((self.root / 'steps').read_text().splitlines(),
                                 ['setup', 'test', 'teardown'])
                self.assertFalse((self.root / 'cleanup-with-child').exists())
                child = int((self.root / 'child.pid').read_text())
                with self.assertRaises(ProcessLookupError):
                    os.kill(child, 0)
            finally:
                # Keep a failing regression test from leaving its 60-second child behind.
                for name in ('child.pid', 'step.pid'):
                    path = self.root / name
                    if path.exists():
                        pid = int(path.read_text())
                        for stop in (os.killpg, os.kill):
                            try:
                                stop(pid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                if process.poll() is None:
                    process.kill()
                    process.wait()

    def test_missing_entrypoint_fails_before_setup(self):
        (self.scenario / 'teardown.sh').unlink()
        result, steps = self.run_scenario()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(steps, [])
        self.assertIn('Missing scenario entrypoint', result.stdout)


if __name__ == '__main__':
    unittest.main()
