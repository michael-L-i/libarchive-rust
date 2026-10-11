#!/usr/bin/env python3
"""bsdtar benchmark: C libarchive vs the Rust port.

Matrix: datasets x formats x {create, extract}. Per case, the executables run in
rotating order over the same output path; readers consume the identical
C-produced archive; the extracted tree is verified against the input. Warm
cache, process startup included, metadata options disabled. A variant wins
with a median more than 5% below C, loses when more than 5% above, else ties.
Requires macOS (/usr/bin/time -l).
"""
import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import datasets as ds  # noqa: E402

FORMATS = {
    'tar': ['--format=ustar'],
    'tar.gz': ['--format=ustar', '-z', '--options=gzip:compression-level=6',
               '--options=gzip:!timestamp'],  # gzip would otherwise embed wall time
    'zip': ['--format=zip', '--options=zip:compression=deflate,zip:compression-level=6'],
    'tar.xz': ['--format=ustar', '-J', '--options=xz:compression-level=6'],
    'tar.zst': ['--format=ustar', '--zstd', '--options=zstd:compression-level=3'],
    '7zip': ['--format=7zip', '--options=7zip:compression=lzma2,7zip:compression-level=6'],
}
NO_METADATA = ['--no-acls', '--no-xattrs', '--no-mac-metadata', '--no-fflags']
ENV = dict(os.environ, LC_ALL='C', TZ='UTC')
TIMEOUT = 30
THRESHOLD = 0.05


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1 << 16), b''):
            h.update(b)
    return h.hexdigest()


def manifest(root):
    return {p.relative_to(root).as_posix(): (p.stat().st_size, sha(p))
            for p in sorted(Path(root).rglob('*')) if p.is_file()}


def run(argv, cwd):
    """Run under /usr/bin/time -l; returns wall time, peak RSS and status."""
    start = time.perf_counter()
    p = subprocess.Popen(['/usr/bin/time', '-l', *map(str, argv)], cwd=cwd, env=ENV,
                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
                         start_new_session=True)
    try:
        _, err = p.communicate(timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        _, err = p.communicate()
        return dict(status='timeout', wall_s=time.perf_counter() - start, error=err[-500:])
    wall = time.perf_counter() - start
    rss = re.search(r'(\d+)\s+maximum resident set size', err)
    return dict(status='ok' if p.returncode == 0 else 'error', wall_s=wall,
                peak_rss_bytes=int(rss[1]) if rss else None,
                error=err[-500:] if p.returncode else '')


def version(exe):
    return subprocess.check_output([exe, '--version'], text=True, env=ENV).strip()


def outcome(ratio):
    return 'win' if ratio < 1 - THRESHOLD else 'loss' if ratio > 1 + THRESHOLD else 'tie'


def measure(tools, inputs, work, args, expected):
    rows, checks, failures = [], [], []
    names = list(tools)
    rotations = lambda r: names[r % len(names):] + names[:r % len(names)]
    out = work / 'timed-output.archive'

    def fail(msg):
        failures.append(msg)
        print('  FAIL', msg, flush=True)

    for d in args.datasets:
        for fmt in args.formats:
            tag = f'{d}/{fmt}'
            archives = {v: work / f'{d}-{fmt}-{v.replace(" ", "_")}.archive' for v in tools}
            hashes = {v: set() for v in tools}
            if 'create' in args.ops or 'extract' in args.ops:
                for r in range(args.repeats):
                    for v in rotations(r):
                        # One shared output path: separate per-tool files showed allocation bias.
                        res = run([tools[v], *FORMATS[fmt], *NO_METADATA, '-cf', out, '-C', inputs / d, '.'], work)
                        if res['status'] != 'ok':
                            fail(f'{tag} create {v}: {res["status"]} {res["error"]}')
                            continue
                        shutil.copyfile(out, archives[v])  # copy outside timing
                        res.update(dataset=d, format=fmt, operation='create', variant=v, repeat=r,
                                   archive_bytes=archives[v].stat().st_size)
                        hashes[v].add(sha(archives[v]))
                        if 'create' in args.ops:
                            rows.append(res)
            if 'C' not in tools or not archives['C'].exists():
                continue
            if 'extract' in args.ops:
                for r in range(args.repeats):
                    for v in rotations(r):
                        with tempfile.TemporaryDirectory(prefix='extract-', dir=work) as dest:
                            res = run([tools[v], *NO_METADATA, '--no-same-owner', '-xf', archives['C'], '-C', dest], work)
                            res.update(dataset=d, format=fmt, operation='extract', variant=v, repeat=r)
                            if res['status'] != 'ok' or manifest(dest) != expected[d]:
                                fail(f'{tag} extract {v}: {res["status"] or "content mismatch"} {res["error"]}')
                                continue
                            rows.append(res)
            for writer, archive in archives.items():
                if not archive.exists():
                    continue
                for reader in dict.fromkeys(['C', names[-1]]):
                    with tempfile.TemporaryDirectory(prefix='cross-', dir=work) as dest:
                        res = run([tools[reader], *NO_METADATA, '--no-same-owner', '-xf', archive, '-C', dest], work)
                        ok = res['status'] == 'ok' and manifest(dest) == expected[d]
                        checks.append(dict(dataset=d, format=fmt, writer=writer, reader=reader, valid=ok))
                        if not ok:
                            fail(f'{tag} {writer} archive read by {reader}')
            if 'Rust before' in tools:
                same = len(hashes['Rust']) == 1 and hashes['Rust'] == hashes['Rust before']
                checks.append(dict(dataset=d, format=fmt, check='Rust and Rust before write identical bytes', valid=same))
            print(f'{d:11s} {fmt:7s} done', flush=True)
    return rows, checks, failures


def summarize(rows, tools, args):
    summary = {}
    for d in args.datasets:
        for fmt in args.formats:
            for op in args.ops:
                for v in tools:
                    s = [r for r in rows if (r['dataset'], r['format'], r['operation'], r['variant']) == (d, fmt, op, v)]
                    if s:
                        summary[d, fmt, op, v] = dict(
                            median_s=statistics.median(r['wall_s'] for r in s),
                            min_s=min(r['wall_s'] for r in s), max_s=max(r['wall_s'] for r in s),
                            peak_mib=statistics.median(r['peak_rss_bytes'] or 0 for r in s) / 1024 ** 2,
                            archive_bytes=s[0].get('archive_bytes'))
    scores = {}
    for v in tools:
        if v == 'C':
            continue
        cases = []
        for (d, fmt, op, var), c in summary.items():
            if var == 'C' and (d, fmt, op, v) in summary:
                ratio = summary[d, fmt, op, v]['median_s'] / c['median_s']
                cases.append(dict(dataset=d, format=fmt, operation=op, ratio=ratio, outcome=outcome(ratio)))
        scores[v] = dict(wins=sum(c['outcome'] == 'win' for c in cases),
                         ties=sum(c['outcome'] == 'tie' for c in cases),
                         losses=sum(c['outcome'] == 'loss' for c in cases),
                         total=len(cases), cases=cases)
    return summary, scores


def markdown(label, meta, tools, summary, scores, checks, failures, args):
    L = [f'# bsdtar benchmark: {label}', '',
         f'{meta["cpu"]}, {meta["platform"]}. {args.repeats} rotating repeat(s); warm cache; '
         'process startup included. Win/loss means median more than 5% below/above C; otherwise tie.', '']
    for v, p in tools.items():
        L.append(f'- {v}: `{p}` ({meta["versions"][v]})')
    L += ['', '## Scorecard (vs C)', '', '| Variant | Wins | Ties | Losses | Cases |', '|---|---:|---:|---:|---:|']
    for v, s in scores.items():
        L.append(f'| {v} | {s["wins"]} | {s["ties"]} | {s["losses"]} | {s["total"]} |')
    others = list(scores)
    L += ['', '## Cases', '',
          '| Dataset | Format | Op | C ms | ' + ' | '.join(f'{v} ms | {v}/C' for v in others) +
          ' | C MiB | ' + ' | '.join(f'{v} MiB' for v in others) + ' | Archive ' + '/C | Archive '.join(others) + '/C |',
          '|---|---|---|---:|' + '---:|---:|' * len(others) + '---:|' + '---:|' * len(others) + '---:|' * len(others)]
    for d in args.datasets:
        for fmt in args.formats:
            for op in args.ops:
                c = summary.get((d, fmt, op, 'C'))
                if not c:
                    continue
                cells = [d, fmt, op, f'{c["median_s"] * 1000:.1f}']
                for v in others:
                    x = summary.get((d, fmt, op, v))
                    sc = next((k for k in scores[v]['cases'] if (k['dataset'], k['format'], k['operation']) == (d, fmt, op)), None)
                    cells += [f'{x["median_s"] * 1000:.1f}', f'{sc["ratio"]:.2f} {sc["outcome"]}'] if x and sc else ['-', '-']
                cells.append(f'{c["peak_mib"]:.0f}')
                cells += [f'{summary[d, fmt, op, v]["peak_mib"]:.0f}' if (d, fmt, op, v) in summary else '-' for v in others]
                for v in others:
                    x = summary.get((d, fmt, op, v))
                    cells.append(f'{x["archive_bytes"] / c["archive_bytes"]:.3f}' if op == 'create' and x else '')
                L.append('| ' + ' | '.join(cells) + ' |')
    bad = [k for k in checks if not k['valid']]
    L += ['', '## Checks', '',
          f'{len(checks)} cross-reader/identity checks, {len(bad)} failed; {len(failures)} run failures.']
    L += [f'- {f}' for f in failures]
    return '\n'.join(L) + '\n'


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--c', required=True, type=Path, help='C bsdtar (reference)')
    ap.add_argument('--rust', required=True, type=Path, help='Rust bsdtar under test')
    ap.add_argument('--rust-before', type=Path, help='earlier Rust bsdtar for a three-way run')
    ap.add_argument('--inputs', type=Path, help='corpus directory (default: generate into <work>/inputs)')
    ap.add_argument('--work', type=Path, default=HERE / 'work', help='scratch directory (default bench/work)')
    ap.add_argument('--out', type=Path, default=HERE / 'out', help='results directory (default bench/out)')
    ap.add_argument('--label', default=time.strftime('%Y%m%d-%H%M%S'))
    ap.add_argument('--formats', nargs='+', choices=FORMATS, default=list(FORMATS))
    ap.add_argument('--datasets', nargs='+', choices=ds.DATASETS, default=ds.DATASETS)
    ap.add_argument('--ops', nargs='+', choices=['create', 'extract'], default=['create', 'extract'])
    ap.add_argument('--repeats', type=int, default=5)
    args = ap.parse_args()
    if not 1 <= args.repeats <= 20:
        ap.error('--repeats must be 1..20')
    tools = {'C': args.c, 'Rust': args.rust}
    if args.rust_before:
        tools['Rust before'] = args.rust_before
    tools = {v: p.resolve() for v, p in tools.items()}
    for v, p in tools.items():
        if not os.access(p, os.X_OK):
            ap.error(f'{v}: {p} is not executable')
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    inputs = args.inputs.resolve() if args.inputs else work / 'inputs'
    if not args.inputs:
        missing = [d for d in args.datasets if not (inputs / d).exists()]
        if missing:
            ds.generate(inputs, missing)
    for d in args.datasets:
        if not (inputs / d).is_dir():
            ap.error(f'dataset {d} not found in {inputs}')
    expected = {d: manifest(inputs / d) for d in args.datasets}
    for p in tools.values():  # pay first-launch and loader costs before measuring
        version(p)
    meta = dict(platform=platform.platform(), machine=platform.machine(),
                cpu=subprocess.check_output(['sysctl', '-n', 'machdep.cpu.brand_string'], text=True).strip(),
                versions={v: version(p) for v, p in tools.items()},
                sha256={v: sha(p) for v, p in tools.items()},
                inputs={d: ds.digest(inputs / d) for d in args.datasets})
    rows, checks, failures = measure(tools, inputs, work, args, expected)
    summary, scores = summarize(rows, tools, args)
    args.out.mkdir(parents=True, exist_ok=True)
    stem = args.out / args.label
    result = dict(meta=meta, args={k: str(v) for k, v in vars(args).items()}, rows=rows, checks=checks,
                  failures=failures, scorecard=scores,
                  summary=[dict(dataset=k[0], format=k[1], operation=k[2], variant=k[3], **v) for k, v in summary.items()])
    stem.with_suffix('.json').write_text(json.dumps(result, indent=2) + '\n')
    md = markdown(args.label, meta, tools, summary, scores, checks, failures, args)
    stem.with_suffix('.md').write_text(md)
    print(md)
    print(f'wrote {stem}.json and {stem}.md')
    return 1 if failures or any(not c['valid'] for c in checks) else 0


if __name__ == '__main__':
    sys.exit(main())
