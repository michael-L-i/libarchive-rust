#!/usr/bin/env python3
"""Benchmark one C bsdtar binary with C and installed Rust shared libraries.

The native macOS run verifies loader paths and public symbol providers before
timing. Rotated paired runs include process startup; extraction consumes the
same C-written archive, and every writer is read by both implementations.
"""
import argparse
import json
import math
import os
from pathlib import Path
import platform
import re
import statistics
import subprocess
import sys
import time

import compare
import datasets


def environment(library):
    env = {key: value for key, value in compare.ENV.items()
           if not key.startswith(('DYLD_', 'LD_'))}
    env['DYLD_LIBRARY_PATH'] = str(library.parent)
    return env


def verify_provider(binary, probe, library, env):
    provider = subprocess.run(compare.timed_command([probe], env), env=env, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              check=True, timeout=30).stdout
    symbols = dict(line.split('\t', 1) for line in provider.splitlines()[1:])
    required = {'archive_read_new', 'archive_write_new', 'archive_read_disk_new',
                'archive_set_error'}
    if set(symbols) != required or any(Path(path).resolve() != library for path in symbols.values()):
        raise RuntimeError(f'public functions did not bind to {library}: {symbols}')
    trace_env = dict(env, DYLD_PRINT_LIBRARIES='1', DYLD_PRINT_BINDINGS='1')
    trace = subprocess.run(compare.timed_command([binary, '--version'], trace_env), env=trace_env, text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=30)
    loaded = [match.group(1) for line in trace.stderr.splitlines()
              if (match := re.search(r'dyld\[\d+\]: <[^>]+> (/.+libarchive[^/]*\.dylib)$', line))]
    if library not in [Path(path).resolve() for path in loaded]:
        raise RuntimeError(f'client loaded an unexpected archive library: {loaded}')
    bindings = [line for line in trace.stderr.splitlines()
                if f'<{binary.name}/bind#' in line and '/_archive_' in line]
    if not bindings or any(f'<{library.name}/_archive_' not in line for line in bindings):
        raise RuntimeError(f'client archive bindings did not select {library}: {bindings}')
    # System frameworks can load their own libarchive.2 transitively; bindings
    # above ensure the measured client's calls do not go to that library.
    return dict(symbols=symbols, loaded_archive_libraries=loaded,
                client_archive_bindings=bindings, version=trace.stdout.strip())


def reject_truncated(binary, environments, work):
    checks = []
    for name, content in [('zip', b'PK\x03\x04' + b'\0' * 16),
                          ('gzip', b'\x1f\x8b\x08\0' + b'\0' * 6 + b'\xff')]:
        archive = work / f'truncated.{name}'
        archive.write_bytes(content)
        for variant, env in environments.items():
            result = subprocess.run([str(binary), '-tf', str(archive)], env=env,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            checks.append(dict(check=f'reject truncated {name}', variant=variant,
                               valid=result.returncode != 0, exit_status=result.returncode,
                               stderr=result.stderr.decode('utf-8', 'replace')))
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--binding-probe', type=Path, required=True)
    parser.add_argument('--c-library', type=Path, required=True)
    parser.add_argument('--rust-library', type=Path, required=True)
    parser.add_argument('--rust-build', required=True,
                        help='release build provenance: source revision, rustc version and flags')
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--label', default=time.strftime('%Y%m%d-%H%M%S'))
    parser.add_argument('--repeats', type=int, default=5)
    parser.add_argument('--startup-repeats', type=int, default=25)
    parser.add_argument('--formats', nargs='+', choices=compare.FORMATS, default=list(compare.FORMATS))
    parser.add_argument('--datasets', nargs='+', choices=datasets.DATASETS, default=datasets.DATASETS)
    args = parser.parse_args()
    if platform.system() != 'Darwin':
        parser.error('native macOS is required for loader verification and /usr/bin/time -l')
    if not 1 <= args.repeats <= 20 or not 1 <= args.startup_repeats <= 200:
        parser.error('repeats must be 1..20 and startup-repeats 1..200')
    if Path(args.label).name != args.label or args.label in ('.', '..'):
        parser.error('label must be a filename without directory components')
    binary, probe = args.binary.resolve(), args.binding_probe.resolve()
    libraries = {'C': args.c_library.resolve(), 'Rust': args.rust_library.resolve()}
    if not all(path.is_file() for path in (binary, probe, *libraries.values())):
        parser.error('binary, probe and both libraries must exist')
    if libraries['C'] == libraries['Rust']:
        parser.error('C and Rust library files must differ')
    environments = {variant: environment(library) for variant, library in libraries.items()}
    verification = {variant: verify_provider(binary, probe, library, environments[variant])
                    for variant, library in libraries.items()}
    tools = {variant: binary for variant in libraries}
    inputs, work = args.inputs.resolve(), args.work.resolve()
    if not all((inputs / name).is_dir() for name in args.datasets):
        parser.error('each selected dataset must exist under --inputs')
    work.mkdir(parents=True, exist_ok=True)
    expected = {name: compare.manifest(inputs / name) for name in args.datasets}
    args.ops = ['create', 'extract']
    rows, checks, failures = compare.measure(tools, inputs, work, args, expected, environments)
    checks.extend(reject_truncated(binary, environments, work))
    startup = []
    for repeat in range(args.startup_repeats):
        for variant in (['C', 'Rust'] if repeat % 2 == 0 else ['Rust', 'C']):
            result = compare.run([binary, '--version'], work, environments[variant])
            result.update(variant=variant, repeat=repeat)
            startup.append(result)
            if result['status'] != 'ok':
                failures.append(f'startup {variant}: {result}')
    summary, scores = compare.summarize(rows, tools, args)
    score = scores['Rust']
    score['geometric_mean_ratio'] = (math.exp(statistics.mean(math.log(case['ratio'])
                                                             for case in score['cases']))
                                     if score['cases'] else None)
    startup_summary = {variant: dict(
        median_s=statistics.median(row['wall_s'] for row in startup if row['variant'] == variant),
        peak_mib=statistics.median(row['peak_rss_bytes'] or 0 for row in startup
                                  if row['variant'] == variant) / 1024 ** 2) for variant in tools}
    meta = dict(platform=platform.platform(), machine=platform.machine(),
                cpu=subprocess.check_output(['sysctl', '-n', 'machdep.cpu.brand_string'], text=True).strip(),
                versions={variant: detail['version'] for variant, detail in verification.items()},
                binary=dict(path=str(binary), sha256=compare.sha(binary)),
                libraries={variant: dict(path=str(path), sha256=compare.sha(path))
                           for variant, path in libraries.items()},
                binding_probe=dict(path=str(probe), sha256=compare.sha(probe)),
                rust_build=args.rust_build,
                verification=verification,
                cc=subprocess.check_output(['cc', '--version'], text=True).strip(),
                inputs={name: datasets.digest(inputs / name) for name in args.datasets})
    result = dict(meta=meta, args={key: str(value) for key, value in vars(args).items()},
                  rows=rows, checks=checks, failures=failures, scorecard=scores,
                  startup=startup, startup_summary=startup_summary,
                  summary=[dict(dataset=key[0], format=key[1], operation=key[2], variant=key[3], **value)
                           for key, value in summary.items()])
    args.out.mkdir(parents=True, exist_ok=True)
    stem = args.out / args.label
    stem.with_suffix('.json').write_text(json.dumps(result, indent=2) + '\n')
    markdown = compare.markdown(args.label, meta, tools, summary, scores, checks, failures, args)
    markdown += ('\nOne identical C client executable loaded each shared library. Public read, write, disk '
                 'and variadic error symbols resolved to the selected library before timing. '
                 f'Geometric mean Rust/C ratio: {score["geometric_mean_ratio"]}.\n\n'
                 '| Startup (`--version`) | C | Rust |\n|---|---:|---:|\n'
                 f'| Median ms | {startup_summary["C"]["median_s"] * 1000:.3f} | '
                 f'{startup_summary["Rust"]["median_s"] * 1000:.3f} |\n'
                 f'| Median peak MiB | {startup_summary["C"]["peak_mib"]:.2f} | '
                 f'{startup_summary["Rust"]["peak_mib"]:.2f} |\n')
    stem.with_suffix('.md').write_text(markdown)
    print(markdown)
    return int(bool(failures) or any(not check['valid'] for check in checks))


if __name__ == '__main__':
    sys.exit(main())
