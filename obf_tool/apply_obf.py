#!/usr/bin/env python3
"""MeshAgent string obfuscation tool (v2).

Rewrites eligible string literals in C sources into calls to generated
decryptors. Plaintext never reaches the compiler: obf_generated.h contains
only encrypted byte arrays + decryptor functions.

Constraints honored (each skipped literal is logged):
  - inside #define lines / #include lines
  - sizeof("...") contexts
  - file-scope initializers, any 'x = "..."' initializer (preceded by '=')
  - adjacent string-literal concatenation ("..." "...")
  - literals > MAX_LEN (handled separately: JS blobs)
  - literals < MIN_LEN
Usage: python3 apply_obf.py --write   (dry-run default)
"""
import os, re, sys, random, json

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGETS = [
    'meshcore/agentcore.c',
    'meshcore/meshinfo.c',
    'meshservice/ServiceMain.c',
    'meshconsole/main.c',
    'microscript/ILibDuktape_ScriptContainer.c',
    'microscript/ILibDuktape_Polyfills.c',
]
MIN_LEN = 6
MAX_LEN = 512

def lex_strings(text):
    """Yield (start, end, raw, is_wide, depth) for string literals, skipping comments/char literals.

    depth = brace nesting depth at the literal's position (0 = file scope).
    """
    i, n = 0, len(text)
    depth = 0
    init_end = -1  # depth below which we're inside a file-scope initializer brace
    init_val = False
    while i < n:
        c = text[i]
        if text.startswith('//', i):
            j = text.find('\n', i)
            i = n if j < 0 else j
            continue
        if text.startswith('/*', i):
            j = text.find('*/', i + 2)
            i = n if j < 0 else j + 2
            continue
        if c == "'" :
            i += 1
            while i < n:
                if text[i] == '\\':
                    i += 2
                    # line continuation inside char literal not expected
                    continue
                if text[i] == "'":
                    i += 1
                    break
                i += 1
            continue
        if c == '{':
            if depth == 0:
                # enclosing statement: initializer at file scope if '=' since last terminator
                stmt = text[max(text.rfind(';', 0, i), text.rfind('}', 0, i), text.rfind('{', 0, i)) + 1:i]
                init_val = ('=' in stmt)
                init_end = depth + 1 if init_val else -1
            depth += 1
            i += 1
            continue
        if c == '}':
            depth -= 1
            if depth < init_end:
                init_end = -1
                init_val = False
            i += 1
            continue
        # wide/string prefix
        wide = False
        if c in 'LuU' and i + 1 < n and text[i+1] == '"':
            wide = True
        if c == '"' or (wide and text[i+1] == '"'):
            start = i
            if wide:
                i += 1
            i += 1  # opening quote
            while i < n:
                ch = text[i]
                if ch == '\\':
                    i += 2
                    continue
                if ch == '"':
                    i += 1
                    break
                i += 1
            yield (start, i, text[start:i], wide, depth, init_val and depth >= init_end)
            continue
        i += 1

def context_ok(text, start, end, raw, wide, depth, in_init):
    """Return (ok, reason)."""
    line_start = text.rfind('\n', 0, start) + 1
    line = text[line_start:text.find('\n', start) if '\n' in text[start:] else len(text)]
    if line.lstrip().startswith('#'):
        return False, 'preprocessor'
    if in_init:
        return False, 'file_scope'
    if len(raw) - 2 - (1 if wide else 0) < MIN_LEN:
        return False, 'too_short'
    if len(raw) - 2 > MAX_LEN:
        return False, 'too_long'
    # sizeof
    pre = text[max(0, start-40):start]
    if re.search(r'sizeof\s*$', pre.strip()):
        return False, 'sizeof'
    # immediately preceded by '=' (initializer) or ',' in a decl? '=' check only
    stripped_pre = pre.rstrip()
    if stripped_pre.endswith('=') or re.search(r'=\s*$', stripped_pre):
        return False, 'initializer'
    # adjacent concatenation: next non-ws char is a quote
    j = end
    while j < len(text) and text[j] in ' \t\n':
        j += 1
    if j < len(text) and (text[j] == '"' or (text[j] in 'LuU' and j+1 < len(text) and text[j+1] == '"')):
        return False, 'concat'
    return True, ''

def unescape(raw, wide):
    body = raw[2 if wide else 1:-1]
    out = bytearray() if wide else bytearray()
    units = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == '\\':
            nxt = body[i+1] if i+1 < len(body) else ''
            mapping = {'n': 10, 't': 9, 'r': 13, '0': 0, '\\': 92, '"': 34, "'": 39, 'a': 7, 'b': 8, 'f': 12, 'v': 11}
            if nxt == '\n':  # line continuation
                i += 2; continue
            if nxt == 'x':
                j = i + 2
                h = ''
                while j < len(body) and body[j] in '0123456789abcdefABCDEF':
                    h += body[j]; j += 1
                units.append(int(h, 16)); i = j; continue
            if nxt in mapping:
                units.append(mapping[nxt]); i += 2; continue
            units.append(ord(nxt)); i += 2; continue
        cp = ord(ch)
        if cp > 127:  # non-ascii: encode utf8 for narrow, utf16le for wide
            if wide:
                units.extend([cp & 0xFFFF])  # BMP only; agent sources are ASCII here
            else:
                units.extend(list(ch.encode('utf-8')))
            i += 1; continue
        units.append(cp); i += 1
    return units

def encrypt_units(units, key):
    enc = []
    for i, b in enumerate(units):
        enc.append((b ^ key[i % len(key)] ^ ((i * 31) & 0xFF)) & 0xFF if not isinstance(b, tuple) else b)
    return enc

def main():
    write = '--write' in sys.argv
    random.seed(os.urandom(16))
    key = [random.randrange(256) for _ in range(4)]
    salts = {}

    all_strings = {}   # tuple(units) -> {'name':..., 'wide':bool}
    files_out = {}
    log = []

    for rel in TARGETS:
        path = os.path.join(ROOT, rel)
        text = open(path, encoding='utf-8', errors='ignore').read()
        repls = []
        skipped = {}
        for (s, e, raw, wide, depth, in_init) in lex_strings(text):
            ok, reason = context_ok(text, s, e, raw, wide, depth, in_init)
            if not ok:
                skipped[reason] = skipped.get(reason, 0) + 1
                continue
            units = unescape(raw, wide)
            k = (tuple(units), wide)
            if k not in all_strings:
                name = 'obf_%s_%04x' % ('w' if wide else 'n', len(all_strings))
                all_strings[k] = {'name': name, 'wide': wide}
            repls.append((s, e, all_strings[k]['name']))
        if write:
            for (s, e, name) in sorted(repls, reverse=True):
                text = text[:s] + name + '_dec()' + text[e:]
            # prepend include at very top (before any #ifdef blocks)
            if 'obf_generated' not in text:
                text = '#include "obf_generated.h"\n' + text
            open(path, 'w', encoding='utf-8').write(text)
        files_out[rel] = len(repls)
        log.append((rel, len(repls), skipped))

    # generate header
    hdr = ['#ifndef OBF_GENERATED_H', '#define OBF_GENERATED_H', '',
           '/* Auto-generated by obf_tool/apply_obf.py - do not edit. */',
           '#include <stddef.h>',
           '#ifdef _WIN32', '#include <windows.h>', '#endif', '']
    for k, meta in sorted(all_strings.items(), key=lambda x: x[1]['name']):
        name, wide = meta['name'], meta['wide']
        units = list(k[0]) + [0]  # nul terminator
        enc = []
        for i, b in enumerate(units):
            enc.append((b ^ key[i % 4] ^ ((i * 31) & 0xFF)) & 0xFF)
        arr = ','.join('0x%02X' % b for b in enc)
        hdr.append('static const unsigned char %s_data[%d] = { %s };' % (name, len(enc), arr))
        if not wide:
            hdr.append('static char* %s_dec(void) { static char buf[%d]; { unsigned i; for (i = 0; i < %d; ++i) buf[i] = (char)(%s_data[i] ^ obf_key(i)); } return buf; }'
                       % (name, len(enc), len(enc), name))
        else:
            hdr.append('static wchar_t* %s_dec(void) { static wchar_t buf[%d]; { unsigned i; for (i = 0; i < %d; ++i) buf[i] = (wchar_t)(%s_data[i] ^ obf_key(i)); } return buf; }'
                       % (name, len(enc), len(enc), name))
        hdr.append('')
    # key helper (must precede decryptors that call it)
    karr = ','.join('0x%02X' % b for b in key)
    hdr.insert(9, 'static const unsigned char obf_keys[4] = { %s };' % karr)
    hdr.insert(10, 'static unsigned char obf_key(unsigned i) { return (unsigned char)(obf_keys[i & 3] ^ ((i * 31) & 0xFF)); }')
    hdr.append('#endif')
    if write:
        open(os.path.join(ROOT, 'obf_generated.h'), 'w').write('\n'.join(hdr))
        # key file for records
        json.dump({'key': key}, open(os.path.join(ROOT, 'obf_tool/key.json'), 'w'))

    for rel, cnt, skipped in log:
        print('%-50s replaced=%-5d skipped=%s' % (rel, cnt, skipped))
    print('total unique strings:', len(all_strings), '| key:', [hex(b) for b in key])
    print('mode:', 'WRITE' if write else 'DRY-RUN')

if __name__ == '__main__':
    main()
