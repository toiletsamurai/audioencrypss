#!/usr/bin/env python3
"""elbasan_stego: Elbasan transposition + authenticated encryption + scattered 16-bit WAV LSB steganography."""
import argparse
import getpass
import hashlib
import hmac
import os
import secrets
import struct
import sys
import unicodedata
import wave
import zlib

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    Cipher = None

ELBASAN_BASE = 0x10500  # U+10500..U+10527 -> 40 glyphs
RADIX = 40
PBKDF2_ITERS = 200_000
CID_SHA, CID_AES = 0, 1  # cipher id, stored in the blob and covered by the HMAC
BLOB_OVERHEAD = 1 + 16 + 16 + 32  # cipher id + salt + iv + HMAC tag
LSB_BYTE = 0 if sys.byteorder == "little" else 1  # byte of a native-endian sample holding its LSB


class StegoError(Exception):
    pass


class _Rng:
    """Deterministic SHA-256 counter PRNG with unbiased bounded integers (stable across Python versions)."""

    def __init__(self, seed):
        self.seed, self.ctr, self.buf = seed, 0, []

    def below(self, n):
        limit = (1 << 64) - (1 << 64) % n
        while True:
            if not self.buf:
                block = hashlib.sha256(self.seed + struct.pack(">Q", self.ctr)).digest()
                self.ctr += 1
                self.buf = list(struct.unpack(">4Q", block))
            w = self.buf.pop()
            if w < limit:
                return w % n


def _norm(passphrase):
    return unicodedata.normalize("NFC", passphrase).encode("utf-8")


# ---- Layer 1: keyed Elbasan base-40 transposition -------------------------------------------

def _elbasan_table(pb):
    """Keyed Fisher-Yates shuffle of the 40 Elbasan code points."""
    table = [ELBASAN_BASE + i for i in range(RADIX)]
    rng = _Rng(hashlib.sha256(pb + b"elbasan_table").digest())
    for i in range(RADIX - 1, 0, -1):
        j = rng.below(i + 1)
        table[i], table[j] = table[j], table[i]
    return table


# Fixed-width radix-40 groups: 3 bytes -> 5 digits, 2 bytes -> 4 digits, 1 byte -> 2 digits.
_WIDTH = {3: 5, 2: 4, 1: 2}
_BYTES = {5: 3, 4: 2, 2: 1}


def to_glyphs(pb, data):
    table, out = _elbasan_table(pb), []
    for i in range(0, len(data), 3):
        chunk = data[i:i + 3]
        n, digits = int.from_bytes(chunk, "big"), []
        for _ in range(_WIDTH[len(chunk)]):
            n, r = divmod(n, RADIX)
            digits.append(table[r])
        out.extend(map(chr, reversed(digits)))
    return "".join(out)


def from_glyphs(pb, text):
    inv = {cp: i for i, cp in enumerate(_elbasan_table(pb))}
    try:
        digits = [inv[ord(c)] for c in text]
    except KeyError:
        raise StegoError("corrupt payload: unexpected symbol in Elbasan stream")
    out = bytearray()
    for i in range(0, len(digits), 5):
        group = digits[i:i + 5]
        if len(group) not in _BYTES:
            raise StegoError("corrupt payload: invalid Elbasan stream length")
        n = 0
        for d in group:
            n = n * RADIX + d
        try:
            out += n.to_bytes(_BYTES[len(group)], "big")
        except OverflowError:
            raise StegoError("corrupt payload: invalid Elbasan group")
    return bytes(out)


# ---- Layer 2: PBKDF2 + (AES-256-CTR | SHA-256-CTR) + HMAC-SHA256 ----------------------------

def _derive(pb, salt):
    k = hashlib.pbkdf2_hmac("sha256", pb, salt, PBKDF2_ITERS, dklen=64)
    return k[:32], k[32:]


def _ctr_sha(key, iv, data):
    ks = b"".join(hashlib.sha256(b"elbasan-ctr" + key + iv + struct.pack(">Q", i)).digest()
                  for i in range((len(data) + 31) // 32))
    x = int.from_bytes(data, "big") ^ int.from_bytes(ks[:len(data)], "big")
    return x.to_bytes(len(data), "big")


def _ctr(cid, key, iv, data):
    if cid == CID_AES:
        c = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
        return c.update(data) + c.finalize()
    return _ctr_sha(key, iv, data)


def seal(pb, plaintext):
    """Returns cid(1) | salt(16) | iv(16) | ciphertext | HMAC-SHA256(32)."""
    cid = CID_AES if Cipher is not None else CID_SHA
    salt, iv = secrets.token_bytes(16), secrets.token_bytes(16)
    enc_key, mac_key = _derive(pb, salt)
    body = bytes([cid]) + salt + iv + _ctr(cid, enc_key, iv, plaintext)
    return body + hmac.new(mac_key, body, hashlib.sha256).digest()


def unseal(pb, blob):
    if len(blob) < BLOB_OVERHEAD:
        raise StegoError("payload too short to be valid")
    body, tag = blob[:-32], blob[-32:]
    cid, salt, iv, ct = body[0], body[1:17], body[17:33], body[33:]
    enc_key, mac_key = _derive(pb, salt)
    if not hmac.compare_digest(hmac.new(mac_key, body, hashlib.sha256).digest(), tag):
        raise StegoError("authentication failed: wrong passphrase, or the audio was "
                         "re-encoded, truncated or tampered with")
    if cid == CID_AES and Cipher is None:
        raise StegoError("payload was encrypted with AES-256-CTR; install 'cryptography' to extract it")
    if cid not in (CID_SHA, CID_AES):
        raise StegoError("unknown cipher id in payload")
    return _ctr(cid, enc_key, iv, ct)


# ---- Layer 3: scattered 16-bit PCM LSB embedding --------------------------------------------

def read_wav(path):
    try:
        with wave.open(path, "rb") as w:
            params, frames = w.getparams(), bytearray(w.readframes(w.getnframes()))
    except (wave.Error, EOFError, OSError) as e:
        raise StegoError(f"cannot read WAV '{path}': {e}")
    if params.sampwidth != 2:
        raise StegoError(f"only 16-bit PCM WAV is supported (got {params.sampwidth * 8}-bit)")
    return params, frames


def write_wav(path, params, frames):
    tmp = f"{path}.{secrets.token_hex(4)}.tmp"
    try:
        with wave.open(tmp, "wb") as w:
            w.setparams(params)
            w.writeframes(bytes(frames))
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


def scatter_positions(pb, n):
    """Yields the first-to-last entries of a keyed random permutation of range(n) (sparse Fisher-Yates)."""
    rng, moved = _Rng(hashlib.sha256(pb + b"lsb_scatter").digest()), {}
    for i in range(n):
        j = i + rng.below(n - i)
        vi = moved.pop(i, i)
        if j == i:
            yield vi
        else:
            vj = moved.get(j, j)
            moved[j] = vi
            yield vj


def check_capacity(params, nsamples, nbytes):
    bits = nbytes * 8
    if bits > nsamples:
        secs = bits / (params.framerate * params.nchannels)
        raise StegoError(f"carrier too short: payload needs {bits} samples but carrier has {nsamples}. "
                         f"Minimum: {bits} samples = {secs:.3f} s at {params.framerate} Hz, "
                         f"{params.nchannels} channel(s)")


def embed(pb, frames, data):
    pos = scatter_positions(pb, len(frames) // 2)
    for byte in data:
        for shift in range(7, -1, -1):
            k = 2 * next(pos) + LSB_BYTE
            frames[k] = (frames[k] & 0xFE) | ((byte >> shift) & 1)


def _take(frames, pos, nbytes):
    out = bytearray()
    for _ in range(nbytes):
        v = 0
        for _ in range(8):
            v = (v << 1) | (frames[2 * next(pos) + LSB_BYTE] & 1)
        out.append(v)
    return bytes(out)


def extract_blob(pb, frames):
    nsamples = len(frames) // 2
    if nsamples < 32:
        raise StegoError("audio too short to contain a payload")
    pos = scatter_positions(pb, nsamples)
    (length,) = struct.unpack(">I", _take(frames, pos, 4))
    if length < BLOB_OVERHEAD or (4 + length) * 8 > nsamples:
        raise StegoError("no valid payload found: wrong passphrase, or no hidden data in this file")
    return _take(frames, pos, length)


# ---- Pipeline + CLI -------------------------------------------------------------------------

def cmd_hide(a, pb):
    if a.message is not None:
        data = a.message.encode("utf-8")
    else:
        try:
            with open(a.file, "rb") as f:
                data = f.read()
        except OSError as e:
            raise StegoError(f"cannot read '{a.file}': {e}")
    glyphs = to_glyphs(pb, data)
    if a.inspect_elbasan:
        more = "..." if len(glyphs) > 96 else ""
        print(f"[elbasan] {len(data)} bytes -> {len(glyphs)} glyphs: {glyphs[:96]}{more}")
    blob = seal(pb, zlib.compress(glyphs.encode("utf-8"), 9))
    payload = struct.pack(">I", len(blob)) + blob
    params, frames = read_wav(a.input)
    nsamples = len(frames) // 2
    check_capacity(params, nsamples, len(payload))
    embed(pb, frames, payload)
    write_wav(a.output, params, frames)
    print(f"hidden {len(data)} bytes ({len(payload)} bytes embedded, {len(payload) * 8}/{nsamples} "
          f"samples used, cipher={'AES-256-CTR' if blob[0] == CID_AES else 'SHA-256-CTR'}) -> {a.output}")


def cmd_extract(a, pb):
    _, frames = read_wav(a.input)
    plain = unseal(pb, extract_blob(pb, frames))
    try:
        data = from_glyphs(pb, zlib.decompress(plain).decode("utf-8"))
    except (zlib.error, UnicodeDecodeError):
        raise StegoError("payload decoded to garbage (corrupt data)")
    if a.output:
        with open(a.output, "wb") as f:
            f.write(data)
        print(f"extracted {len(data)} bytes -> {a.output}")
        return
    try:
        sys.stdout.write(data.decode("utf-8") + "\n")
    except UnicodeDecodeError:
        raise StegoError(f"recovered {len(data)} bytes of binary data; use -o to write them to a file")


def build_parser():
    p = argparse.ArgumentParser(prog="elbasan_stego", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    h = sub.add_parser("hide", help="embed a message or file into a 16-bit PCM WAV")
    h.add_argument("-i", "--input", required=True, help="carrier .wav")
    h.add_argument("-o", "--output", required=True, help="stego .wav to write")
    h.add_argument("-p", "--passphrase", help="passphrase (prompted if omitted)")
    src = h.add_mutually_exclusive_group(required=True)
    src.add_argument("-m", "--message", help="text message to hide")
    src.add_argument("-f", "--file", help="file to hide")
    h.add_argument("--inspect-elbasan", action="store_true", help="preview the scrambled Elbasan glyph stream")
    x = sub.add_parser("extract", help="recover hidden data from a stego WAV")
    x.add_argument("-i", "--input", required=True, help="stego .wav")
    x.add_argument("-p", "--passphrase", help="passphrase (prompted if omitted)")
    x.add_argument("-o", "--output", help="write recovered data to this file (default: stdout)")
    return p


def main(argv=None):
    a = build_parser().parse_args(argv)
    try:
        pw = a.passphrase if a.passphrase is not None else getpass.getpass("Passphrase: ")
        if not pw:
            raise StegoError("passphrase must not be empty")
        if a.cmd == "hide" and os.path.abspath(a.input) == os.path.abspath(a.output):
            raise StegoError("output must differ from the carrier file")
        pb = _norm(pw)
        (cmd_hide if a.cmd == "hide" else cmd_extract)(a, pb)
    except (StegoError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
