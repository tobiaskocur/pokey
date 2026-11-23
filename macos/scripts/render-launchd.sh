#!/bin/sh
# Xcode build phase of PokeyHost: writes the SMAppService launchd plists with the
# configured bundle prefix into Contents/Library/LaunchDaemons and LaunchAgents.
set -eu
: "${POKEY_BUNDLE_PREFIX:?}" "${SRCROOT:?}" "${TARGET_BUILD_DIR:?}" "${CONTENTS_FOLDER_PATH:?}"
case "$POKEY_BUNDLE_PREFIX" in
    *[!A-Za-z0-9.-]*) echo "POKEY_BUNDLE_PREFIX has invalid characters" >&2; exit 1 ;;
esac
OUT="$TARGET_BUILD_DIR/$CONTENTS_FOLDER_PATH/Library"
mkdir -p "$OUT/LaunchDaemons" "$OUT/LaunchAgents"
sed "s/@PREFIX@/$POKEY_BUNDLE_PREFIX/g" "$SRCROOT/Config/launchd/netd.plist.in" > "$OUT/LaunchDaemons/netd.plist"
sed "s/@PREFIX@/$POKEY_BUNDLE_PREFIX/g" "$SRCROOT/Config/launchd/ui.plist.in" > "$OUT/LaunchAgents/ui.plist"
plutil -lint "$OUT/LaunchDaemons/netd.plist" "$OUT/LaunchAgents/ui.plist"
