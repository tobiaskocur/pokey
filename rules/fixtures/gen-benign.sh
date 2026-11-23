#!/bin/sh
# Regenerates the benign corpus (rules/benign) from ffmpeg test patterns. Every
# file must scan CLEAN; `edr-rulec test --benign` is the false-positive gate.
# Add real-world images from cameras and editors here as they are collected.
set -eu
cd "$(dirname "$0")/../benign"
f() { s=$1; shift; ffmpeg -loglevel error -y -f lavfi -i "testsrc2=s=$s" -frames:v 1 "$@"; }
f 320x240 testsrc_rgb.png
f 64x64 -pix_fmt rgba testsrc_rgba.png
f 128x96 -pix_fmt rgb48be testsrc_16bit.png
f 200x150 -pix_fmt gray gray.png
f 320x240 testsrc.tif
f 160x120 -compression_algo deflate testsrc_deflate.tif
f 320x240 testsrc.jpg
f 128x128 -c:v libaom-av1 -still-picture 1 testsrc.avif
