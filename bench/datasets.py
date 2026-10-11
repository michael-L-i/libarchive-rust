#!/usr/bin/env python3
"""Deterministically generate the eight benchmark datasets.

Byte-identical to the frozen corpus: text, random, records, documents.
Approximations (same generator, different seed text or substitute bytes):
source, mixed, many-files (built from upstream's sources instead of the
unrecorded original text) and compiled (synthetic object-like bytes instead of
a copy of an old bsdtar binary). See bench/README.md.
"""
import argparse
import hashlib
import json
import os
import random
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DATASETS = ['text', 'random', 'source', 'mixed', 'compiled', 'records', 'documents', 'many-files']
MIB = 1024 * 1024
MTIME = 1700000000
# Manifest digests (see digest()) of the frozen corpus, round8-suite/inputs.
FROZEN = {
    'text': 'de17c72dc28903901e6fde9d6a7eb5d3ea9c7f67fdd2762900d43f6099cc5b1c',
    'random': '8f43686b072e8d14b14fd789016457a5e08a1d13024d68a25a4a02be0b1a411d',
    'source': '1e973e6937421b3019667530af08ded37eb7478f2a288fabacbd2889efc23924',
    'mixed': 'be904dc91968f3e2b312b3699aa2022e6ad731231f18b2b9887e786914cfbdfb',
    'compiled': 'c747edd0de28b1032dacc2a9b0415b65febd3cf550087acf450eecd524287297',
    'records': 'faa0c294e89730cc7d9ddeddbeb723db4f291cf0477234c7a49a450d2be12b86',
    'documents': '843dd375edcbe0acf08d6e0e91126f393104580cd95aec464f53b59f1c335b07',
    'many-files': 'c28b4e2210d7a78edec498f9e3c90d4658c9885cca3b52c30c4a6dbf92f66898',
}
EXACT = {'text', 'random', 'records', 'documents'}


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1 << 16), b''):
            h.update(b)
    return h.hexdigest()


def digest(root):
    """SHA-256 over the sorted (relative path, size, file SHA-256) listing."""
    h = hashlib.sha256()
    for p in sorted(Path(root).rglob('*')):
        if p.is_file():
            h.update(f'{p.relative_to(root).as_posix()}\0{p.stat().st_size}\0{sha(p)}\n'.encode())
    return h.hexdigest()


def source_text():
    """Fixed text: upstream's libarchive/*.[ch] sorted by name (pinned submodule)."""
    d = REPO / 'upstream' / 'libarchive' / 'libarchive'
    files = sorted(p for p in d.iterdir() if p.suffix in ('.c', '.h'))
    if not files:
        sys.exit(f'{d} is empty: run `git submodule update --init upstream/libarchive`')
    return b''.join(p.read_bytes() for p in files)


def tile(data, length):
    return (data * (length // len(data) + 1))[:length]


def put(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def gen_text_random(out):
    # benchmark.py generate(path, 16): four 4 MiB parts each.
    rng = random.Random(20261009)
    line = (b'{"service":"archive","level":"info","message":"repeatable benchmark",'
            b'"timestamp":"2026-10-09T00:00:00Z"}\n')
    size = 16 * MIB // 4
    for i in range(4):
        put(out['text'] / f'part-{i}.txt', tile(line, size))
        put(out['random'] / f'part-{i}.bin', rng.randbytes(size))


def gen_source_mixed(out, text):
    n = 16 * MIB
    body = tile(text, n)
    noise = random.Random(20261009).randbytes(n)
    # Alternate noise and source blocks, with abrupt entropy changes.
    mixed = b''.join((body if i // 65536 % 2 else noise)[i:i + 65536] for i in range(0, n, 65536))
    put(out['source'] / 'data', body)
    put(out['mixed'] / 'data', mixed)


def gen_compiled(out, text):
    """Synthetic stand-in for a 4.7 MB executable: 4-byte opcode words with
    repeating operand patterns, symbol-like strings from the source text, zero
    padding and a few high-entropy islands (relocations/constants)."""
    rng = random.Random(4812)
    words = text.decode("ascii", "ignore").split()
    idents = [w.encode() for w in words if 4 <= len(w) <= 30 and w.isidentifier()]
    ops = [rng.getrandbits(32) & 0xFFE0FFFF for _ in range(20)]
    buf = bytearray()
    target = 4924088  # size of the frozen compiled input
    while len(buf) < target:
        r = rng.random()
        if r < 0.62:    # code: opcode with small register/immediate fields
            for _ in range(rng.randrange(40, 400)):
                w = rng.choice(ops) | (rng.choice((1, 2, 3, 8, 29, 30)) << 16) | rng.choice((0, 0, 0, 4, 8, 16))
                buf += w.to_bytes(4, 'little')
        elif r < 0.74:  # string/symbol table
            for _ in range(rng.randrange(20, 200)):
                buf += rng.choice(idents) + b'\0'
        elif r < 0.97:  # zero padding / tables of small ints
            buf += bytes(rng.randrange(16, 512))
            buf += b''.join(rng.randrange(4096).to_bytes(4, 'little') for _ in range(rng.randrange(8, 128)))
        else:           # high-entropy island
            buf += rng.randbytes(rng.randrange(64, 512))
    put(out['compiled'] / 'data', bytes(buf[:target]))


def gen_records(out):
    # round4_inputs.py: rng 381947, records is its first consumer.
    rng = random.Random(381947)
    services = ['api', 'search', 'worker', 'cache', 'billing', 'web']
    methods = ['GET', 'POST', 'PUT', 'DELETE']
    buf = bytearray()
    while len(buf) < 4 * MIB:
        rec = dict(service=rng.choice(services), method=rng.choice(methods),
                   request=f'{rng.getrandbits(128):032x}',
                   user=rng.randrange(100000), status=rng.choice([200, 200, 200, 404, 503]),
                   latency_us=rng.randrange(200000), bytes=rng.randrange(1000000),
                   route=f'/v1/items/{rng.randrange(10000)}',
                   timestamp=1700000000 + rng.randrange(86400))
        buf.extend(json.dumps(rec, separators=(',', ':')).encode() + b'\n')
    put(out['records'] / 'data', bytes(buf[:4 * MIB]))


def gen_documents(out):
    # round5_inputs.py: the telemetry pass runs first and advances the rng.
    rng = random.Random(7319582)
    tel = bytearray(b'time,sensor,temperature,pressure,reading\n')
    while len(tel) < 4 * MIB:
        i = len(tel)
        tel.extend(f'{1700000000 + i // 100},{rng.randrange(64)},'
                   f'{rng.randrange(-200, 450) / 10:.1f},'
                   f'{rng.randrange(95000, 105000)},{rng.getrandbits(24)}\n'.encode())
    phrases = ['Archive validation: documents and attachments.\n',
               'Les documents ont été enregistrés avec leurs pièces jointes.\n',
               '文書と添付ファイルを保存しました。\n',
               'تم حفظ المستندات والمرفقات.\n',
               'Документы и вложения сохранены.\n']
    doc = bytearray()
    while len(doc) < 4 * MIB:
        doc.extend((rng.choice(phrases) * rng.randrange(1, 40)).encode())
        doc.extend(f'item={rng.getrandbits(48):012x}\n'.encode())
        if rng.randrange(8) == 0:
            doc.extend(rng.randbytes(rng.randrange(64, 8192)))
    put(out['documents'] / 'data', bytes(doc[:4 * MIB]))


def gen_many(out, text):
    for i in range(2048):
        off = (i * 137) % (len(text) - 2048)
        put(out['many-files'] / f'group-{i // 32:03d}' / f'item-{i:04d}.txt',
            (f'File {i:04d}\n'.encode() + text[off:off + 2048])[:2048])


def normalize(root):
    for p in [root, *root.rglob('*')]:
        os.chmod(p, 0o755 if p.is_dir() else 0o644)
        os.utime(p, (MTIME, MTIME))


def generate(dest, names):
    dest = Path(dest)
    out = {n: dest / n for n in DATASETS}
    for n in names:
        shutil.rmtree(out[n], ignore_errors=True)
    text = source_text() if set(names) & {'source', 'mixed', 'compiled', 'many-files'} else b''
    if set(names) & {'text', 'random'}:
        gen_text_random(out)
    if set(names) & {'source', 'mixed'}:
        gen_source_mixed(out, text)
    if 'compiled' in names:
        gen_compiled(out, text)
    if 'records' in names:
        gen_records(out)
    if 'documents' in names:
        gen_documents(out)
    if 'many-files' in names:
        gen_many(out, tile(text, 2 * MIB + 2048))
    # text and random are written together; drop the one not requested.
    for n in ('text', 'random'):
        if n not in names:
            shutil.rmtree(out[n], ignore_errors=True)
    for n in names:
        normalize(out[n])


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('dest', type=Path, help='output directory (one subdirectory per dataset)')
    ap.add_argument('--datasets', nargs='+', choices=DATASETS, default=DATASETS)
    ap.add_argument('--from', dest='frozen', type=Path, metavar='DIR',
                    help='copy datasets from an existing corpus (e.g. the frozen one) instead of generating')
    args = ap.parse_args()
    args.dest.mkdir(parents=True, exist_ok=True)
    if args.frozen:
        for n in args.datasets:
            shutil.rmtree(args.dest / n, ignore_errors=True)
            shutil.copytree(args.frozen / n, args.dest / n)
            normalize(args.dest / n)
    else:
        generate(args.dest, args.datasets)
    for n in args.datasets:
        d = digest(args.dest / n)
        files = [p for p in (args.dest / n).rglob('*') if p.is_file()]
        ref = FROZEN.get(n)
        note = '' if args.frozen else ('' if ref is None else ' (identical to frozen)' if d == ref else ' (differs from frozen)')
        print(f'{n:11s} {len(files):5d} files {sum(p.stat().st_size for p in files):>10,d} B  {d}{note}')


if __name__ == '__main__':
    main()
