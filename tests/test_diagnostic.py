"""Exercise orchestration with synthetic evidence; never inspect the runner's SSH/logs."""
import csv
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PATH_LINE = 'export PATH=/usr/sbin:/usr/bin:/sbin:/bin'
MOCK = r'''#!/usr/bin/python3
import hashlib, json, os, pathlib, sys, time
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
if name == 'sudo':
    if args == ['-v']: sys.exit(0)
    if args and args[0] == '-n': args.pop(0)
    os.execvp(args[0], args)
if name == 'awk':
    if args and args[-1] == '/etc/passwd':
        print('fixture:uid=1000:gid=1000:home=/home/fixture:shell=/bin/bash')
        sys.exit(0)
    os.execv('/usr/bin/awk', ['awk', *args])
if name == 'curl':
    if os.environ.get('USC_TEST_DOWNLOAD_FAIL') == '1': sys.exit(22)
    dest = pathlib.Path(args[args.index('--output') + 1])
    if dest.name == 'revision.json':
        if os.environ.get('USC_TEST_BAD_REVISION') == '1':
            dest.write_text('{"sha": "invalid"}')
        else:
            dest.write_text(json.dumps({'sha': 'a' * 40}))
    elif dest.name == 'SHA256SUMS':
        digest = hashlib.sha256(b'echo SHOULD_NOT_EXECUTE\n').hexdigest() if os.environ.get('USC_TEST_GOOD_DOWNLOAD') == '1' else '0' * 64
        dest.write_text(digest + '  ubuntu-security-check.sh\n')
    else:
        dest.write_text('echo SHOULD_NOT_EXECUTE\n')
    sys.exit(0)
if name == 'ss' and os.environ.get('USC_TEST_FAIL') == '1':
    print('fixture: permission denied', file=sys.stderr)
    sys.exit(7)
if name == 'ss' and os.environ.get('USC_TEST_TIMEOUT') == '1':
    time.sleep(8)
if name == 'bash':
    if args and args[0].endswith('/ubuntu-security-check.sh'):
        print('DIAGNOSTIC_EXECUTED ' + json.dumps(args[1:]))
    elif any('/usr/sbin/sshd' in a for a in args):
        print('permitrootlogin no\npasswordauthentication no')
    else:
        print('Synthetic composite-command evidence (no host data read)')
else:
    print('Synthetic ' + name + ': </pre><script>alert("x")</script> & ```')
'''


class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='usc-test-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.bin = self.base / 'bin'
        self.bin.mkdir()
        for name in ('sudo', 'awk', 'bash', 'who', 'last', 'lastb', 'journalctl',
                     'ss', 'ufw', 'nft', 'iptables-save', 'ip6tables-save',
                     'getent', 'ps', 'systemctl', 'apt', 'df', 'curl'):
            path = self.bin / name
            path.write_text(MOCK)
            path.chmod(0o700)
        # Replace only PATH in a temporary copy so fixed production command names
        # resolve to fixtures. The production script has no test mode or PATH override.
        self.script = self.base / 'diagnostic.sh'
        text = (ROOT / 'ubuntu-security-check.sh').read_text()
        self.assertEqual(text.count(PATH_LINE), 1)
        self.script.write_text(text.replace(PATH_LINE, f'export PATH={self.bin}:/usr/sbin:/usr/bin:/sbin:/bin'))

    def run_script(self, *args, env=None):
        return subprocess.run(['/bin/bash', str(self.script), *args], cwd=self.base,
                              text=True, capture_output=True, timeout=45,
                              env={**os.environ, **(env or {})})

    def test_reports_archive_checksums_and_escaping(self):
        report = self.base / 'report with spaces'
        result = self.run_script('--sudo', '--zip', '--output', str(report))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        with (report / 'checks.tsv').open() as stream:
            rows = list(csv.DictReader(stream, delimiter='\t'))
        self.assertEqual(len(rows), 27)
        self.assertTrue(all(r['status'] == 'COLLECTED' for r in rows))
        html = (report / 'report.html').read_text()
        self.assertNotIn('<script>', html)
        self.assertIn('&lt;script&gt;', html)
        self.assertIn('Content-Security-Policy', html)
        self.assertIn('    Synthetic', (report / 'report.md').read_text())
        self.assertEqual(stat.S_IMODE(report.stat().st_mode), 0o700)
        for path in report.rglob('*'):
            if path.is_file(): self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        for line in (report / 'SHA256SUMS').read_text().splitlines():
            expected, name = line.split('  ', 1)
            self.assertEqual(hashlib.sha256((report / name).read_bytes()).hexdigest(), expected)
        archive = report.with_name(report.name + '.zip')
        self.assertEqual(stat.S_IMODE(archive.stat().st_mode), 0o600)
        with zipfile.ZipFile(archive) as z:
            self.assertIsNone(z.testzip())
            self.assertIn(report.name + '/report.html', z.namelist())
            self.assertTrue(all(not n.startswith('/') and '..' not in Path(n).parts for n in z.namelist()))

    def test_existing_output_is_never_overwritten(self):
        target = self.base / 'existing'
        target.mkdir()
        sentinel = target / 'keep'
        sentinel.write_text('preserve')
        result = self.run_script('--output', str(target))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(sentinel.read_text(), 'preserve')
        self.assertFalse((target / 'report.md').exists())

    def test_errors_are_reported_as_incomplete(self):
        target = self.base / 'error-report'
        result = self.run_script('--sudo', '--format', 'md', '--output', str(target), env={'USC_TEST_FAIL': '1'})
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('08-listeners\tERROR\t7', (target / 'checks.tsv').read_text())
        self.assertFalse((target / 'report.html').exists())

    def test_real_command_timeout(self):
        target = self.base / 'timeout-report'
        result = self.run_script('--sudo', '--timeout', '5', '--format', 'md', '--output', str(target), env={'USC_TEST_TIMEOUT': '1'})
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('08-listeners\tTIMEOUT\t124', (target / 'checks.tsv').read_text())

    @unittest.skipIf(os.geteuid() == 0, 'Needs an unprivileged runner')
    def test_unprivileged_checks_are_explicitly_skipped(self):
        target = self.base / 'unprivileged'
        result = self.run_script('--format', 'md', '--output', str(target))
        self.assertEqual(result.returncode, 1)
        self.assertIn('05-ssh-accepted\tSKIPPED', (target / 'checks.tsv').read_text())

    def test_invalid_options_fail_before_collection(self):
        for args in (('--days', '0'), ('--days', '366'), ('--days', '$(id)'),
                     ('--timeout', '4'), ('--timeout', '301'), ('--format', 'xml'),
                     ('--output',), ('--no-such-option',)):
            with self.subTest(args=args):
                result = self.run_script(*args)
                self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse((self.base / 'reports').exists())

    def test_existing_archive_is_preserved(self):
        target = self.base / 'archive-collision'
        archive = target.with_name(target.name + '.zip')
        archive.write_bytes(b'preserve')
        result = self.run_script('--sudo', '--zip', '--output', str(target))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(archive.read_bytes(), b'preserve')
        self.assertTrue((target / 'report.md').exists())

    def test_bootstrap_ref_and_checksum_rejection(self):
        helper = self.base / 'helper.sh'
        helper.write_text((ROOT / 'run-from-github.sh').read_text().replace(
            PATH_LINE, f'export PATH={self.bin}:/usr/sbin:/usr/bin:/sbin:/bin'))
        for ref in ('invalid-ref', 'a' * 40):
            result = subprocess.run(['/bin/bash', str(helper), '--ref', ref],
                                    cwd=self.base, text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertNotIn('SHOULD_NOT_EXECUTE', result.stdout)
        self.assertIn('Checksum mismatch', result.stderr)

    def test_bootstrap_download_failure_never_executes(self):
        helper = self.base / 'helper.sh'
        helper.write_text((ROOT / 'run-from-github.sh').read_text().replace(
            PATH_LINE, f'export PATH={self.bin}:/usr/sbin:/usr/bin:/sbin:/bin'))
        result = subprocess.run(['/bin/bash', str(helper), '--ref', 'a' * 40],
                                cwd=self.base, text=True, capture_output=True, timeout=10,
                                env={**os.environ, 'USC_TEST_DOWNLOAD_FAIL': '1'})
        self.assertEqual(result.returncode, 22)
        self.assertNotIn('Running the diagnostic', result.stdout)

    def test_bootstrap_main_resolution_and_option_forwarding(self):
        helper = self.base / 'helper.sh'
        helper.write_text((ROOT / 'run-from-github.sh').read_text().replace(
            PATH_LINE, f'export PATH={self.bin}:/usr/sbin:/usr/bin:/sbin:/bin'))
        result = subprocess.run(['/bin/bash', str(helper), '--', '--sudo', '--zip', '--days', '14'],
                                cwd=self.base, text=True, capture_output=True, timeout=10,
                                env={**os.environ, 'USC_TEST_GOOD_DOWNLOAD': '1'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Verified diagnostic source at commit: ' + 'a' * 40, result.stdout)
        self.assertIn('DIAGNOSTIC_EXECUTED ["--sudo", "--zip", "--days", "14"]', result.stdout)

    def test_bootstrap_invalid_resolved_commit_never_executes(self):
        helper = self.base / 'helper.sh'
        helper.write_text((ROOT / 'run-from-github.sh').read_text().replace(
            PATH_LINE, f'export PATH={self.bin}:/usr/sbin:/usr/bin:/sbin:/bin'))
        result = subprocess.run(['/bin/bash', str(helper)], cwd=self.base,
                                text=True, capture_output=True, timeout=10,
                                env={**os.environ, 'USC_TEST_BAD_REVISION': '1'})
        self.assertEqual(result.returncode, 2)
        self.assertNotIn('DIAGNOSTIC_EXECUTED', result.stdout)


if __name__ == '__main__':
    unittest.main(verbosity=2)
