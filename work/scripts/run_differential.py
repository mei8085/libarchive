#!/usr/bin/env python3
"""
Differential runner: feeds every crafted sample to
  1) locally built libarchive (harness)
  2) libarchive built with ASan/UBSan (harness_asan)
  3) GNU tar 1.35 (independent implementation)
  4) Python tarfile (second independent implementation, --list only)
Each extraction goes into a fresh empty directory.
"""
import os
import subprocess
import sys

ROOT = "/srv/fb2/mei8085/0070-libarchive-5-c88eda7f/work"
SAMP = os.path.join(ROOT, "samples")
SCRIPTS = os.path.join(ROOT, "scripts")
RUNS = os.path.join(ROOT, "runs")
os.makedirs(RUNS, exist_ok=True)


def run(cmd, cwd=None, timeout=120):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                           timeout=timeout)
        out = p.stdout + (("\n[stderr]\n" + p.stderr) if p.stderr else "")
        return "rc=%d" % p.returncode, out.strip()
    except subprocess.TimeoutExpired:
        return "TIMEOUT", "(killed after %ds)" % timeout


def py_tarfile_list(path):
    code = (
        "import sys,tarfile\n"
        "tf=tarfile.open(sys.argv[1])\n"
        "try:\n"
        "  for m in tf:\n"
        "    print('entry', repr(m.name), 'size', m.size, 'type', m.type)\n"
        "    try:\n"
        "      f=tf.extractfile(m)\n"
        "      if f is not None:\n"
        "        d=f.read(); print('  data', len(d), repr(d[:32]))\n"
        "    except Exception as e: print('  DATA-ERR', type(e).__name__, e)\n"
        "except Exception as e:\n"
        "  print('ITER-ERR', type(e).__name__, e)\n"
        "print('offset_end', tf.offset)\n"
    )
    return run([sys.executable, "-I", "-c", code, path])


def main():
    samples = sorted(f for f in os.listdir(SAMP) if f.endswith(".tar"))
    report = []
    for name in samples:
        path = os.path.join(SAMP, name)
        block = ["=" * 78, "SAMPLE %s" % name, "=" * 78]

        block.append("\n--- (1) libarchive harness (Debug, local build) ---")
        rc, out = run([os.path.join(SCRIPTS, "harness"), path])
        block.append(rc + "\n" + out)

        block.append("\n--- (2) libarchive harness ASan+UBSan ---")
        env = dict(os.environ,
                   ASAN_OPTIONS="detect_leaks=0:abort_on_error=0",
                   UBSAN_OPTIONS="halt_on_error=0:print_stacktrace=0")
        try:
            p = subprocess.run([os.path.join(SCRIPTS, "harness_asan"), path],
                               capture_output=True, text=True, timeout=120,
                               env=env)
            out = p.stdout + (("\n[stderr]\n" + p.stderr) if p.stderr else "")
            block.append("rc=%d\n%s" % (p.returncode, out.strip()))
        except subprocess.TimeoutExpired:
            block.append("TIMEOUT")

        block.append("\n--- (3) GNU tar --list ---")
        rc, out = run(["tar", "--format=ustar", "-tvf", path])
        block.append(rc + "\n" + out)

        ext_dir = os.path.join(RUNS, name + ".gnu_extract")
        os.makedirs(ext_dir, exist_ok=True)
        block.append("\n--- (3b) GNU tar --extract into fresh dir ---")
        rc, out = run(["tar", "-xf", path], cwd=ext_dir)
        block.append(rc + "\n" + out)
        got = []
        for dp, _, fns in os.walk(ext_dir):
            for fn in fns:
                fp = os.path.join(dp, fn)
                got.append(os.path.relpath(fp, ext_dir) +
                           " (%d B)" % os.path.getsize(fp))
        block.append("extracted files: " + (", ".join(sorted(got)) or "(none)"))

        block.append("\n--- (4) Python tarfile (stdlib) ---")
        rc, out = py_tarfile_list(path)
        block.append(rc + "\n" + out)

        report.append("\n".join(block))

    text = "\n\n".join(report) + "\n"
    with open(os.path.join(ROOT, "differential_runs.txt"), "w") as f:
        f.write(text)
    print(text)


if __name__ == "__main__":
    main()
