#!/usr/bin/env python3
"""Regenerate the rule fixtures in this directory (deterministic).

Run: python3 rules/fixtures/gen.py
Expectations for every fixture live in rules/tests.json.
"""
import os
import struct
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))


def chunk(ctype: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + ctype + data + struct.pack(">I", zlib.crc32(ctype + data))


def png(width=2, height=2, extra_chunks=b"", trailer=b"", bad_crc=False) -> bytes:
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    # Pixel data for at most 2x2; oversized headers are the point of some fixtures.
    raw = b"".join(b"\x00" + b"\x80\x40\x20" * min(width, 2) for _ in range(min(height, 2)))
    idat = chunk(b"IDAT", zlib.compress(raw, 9))
    if bad_crc:
        idat = idat[:-1] + bytes([idat[-1] ^ 0xFF])
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + extra_chunks + idat + chunk(b"IEND", b"") + trailer


MACHO = bytes.fromhex("cffaedfe0c000001") + b"\x00" * 24


def tiff(loop=False, out_of_file=False) -> bytes:
    # Little-endian, one 1x1 8-bit grey strip.
    entries = [
        (256, 3, 1, 1),  # ImageWidth
        (257, 3, 1, 1),  # ImageLength
        (258, 3, 1, 8),  # BitsPerSample
        (259, 3, 1, 1),  # Compression none
        (262, 3, 1, 1),  # Photometric BlackIsZero
        (273, 4, 1, 0),  # StripOffsets (patched below)
        (277, 3, 1, 1),  # SamplesPerPixel
        (278, 3, 1, 1),  # RowsPerStrip
        (279, 4, 1, 1),  # StripByteCounts
    ]
    if out_of_file:
        entries.append((305, 2, 64, 0x7FFF0000))  # Software string far outside the file
    ifd_off = 8
    ifd_len = 2 + 12 * len(entries) + 4
    strip_off = ifd_off + ifd_len
    out = b"II*\x00" + struct.pack("<I", ifd_off)
    body = struct.pack("<H", len(entries))
    for tag, typ, n, val in entries:
        if tag == 273:
            val = strip_off
        if typ == 3 and n == 1:
            body += struct.pack("<HHIHH", tag, typ, n, val, 0)
        else:
            body += struct.pack("<HHII", tag, typ, n, val)
    body += struct.pack("<I", ifd_off if loop else 0)
    return out + body + b"\x80"


def box(btype: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", 8 + len(payload)) + btype + payload


def heic(overflow=False, deep=0) -> bytes:
    ftyp = box(b"ftyp", b"heic" + struct.pack(">I", 0) + b"mif1heic")
    hdlr = box(b"hdlr", b"\x00" * 8 + b"pict" + b"\x00" * 13)
    ispe = box(b"ispe", b"\x00" * 4 + struct.pack(">II", 1, 1))
    iprp = box(b"iprp", box(b"ipco", ispe))
    meta = box(b"meta", b"\x00" * 4 + hdlr + iprp)
    mdat_payload = b"\x00" * 16
    if overflow:
        # mdat claims far more bytes than the file has.
        mdat = struct.pack(">I", 0x7FFFFFF0) + b"mdat" + mdat_payload
    else:
        mdat = box(b"mdat", mdat_payload)
    if deep:
        inner = box(b"free", b"")
        for _ in range(deep):
            inner = box(b"moov", inner)
        return ftyp + inner
    return ftyp + meta + mdat


FIXTURES = {
    "png_valid.png": png(),
    "png_text_chunk.png": png(extra_chunks=chunk(b"tEXt", b"Comment\x00made by gen.py")),
    "png_trailing_data.png": png(trailer=b"\x00" * 64 + b"appended"),
    "png_bad_crc.png": png(bad_crc=True),
    "png_huge_dimensions.png": png(width=0x80000000, height=1),
    "png_trailing_macho.png": png(trailer=MACHO),
    "png_script.png": png(extra_chunks=chunk(b"tEXt", b"x\x00<script>alert(1)</script>")),
    "tiff_valid.tif": tiff(),
    "tiff_ifd_loop.tif": tiff(loop=True),
    "tiff_tag_outside.tif": tiff(out_of_file=True),
    "heic_valid.heic": heic(),
    "heic_box_overflow.heic": heic(overflow=True),
    "heic_deep_nesting.heic": heic(deep=40),
    "not_an_image.bin": bytes(range(256)),
}


def main() -> None:
    for name, data in FIXTURES.items():
        with open(os.path.join(HERE, name), "wb") as f:
            f.write(data)
    print(f"wrote {len(FIXTURES)} fixtures to {HERE}")


if __name__ == "__main__":
    main()
