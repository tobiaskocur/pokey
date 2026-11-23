#!/bin/sh
# Installer postinstall (root): creates the hidden service accounts used by
# edr-netd (_edrnet) and edr-inspector (_edrinspect). Idempotent.
set -eu
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }

free_id() {
    # First unused id in the 400-499 system range for both users and groups.
    used=$( { dscl . -list /Users UniqueID; dscl . -list /Groups PrimaryGroupID; } | awk '{print $2}')
    i=400
    while [ $i -lt 500 ]; do
        echo "$used" | grep -qx "$i" || { echo $i; return; }
        i=$((i + 1))
    done
    echo "no free system id" >&2; exit 1
}

create() {
    name=$1 realname=$2
    if dscl . -read "/Users/$name" >/dev/null 2>&1; then return; fi
    id=$(free_id)
    dscl . -create "/Groups/$name"
    dscl . -create "/Groups/$name" PrimaryGroupID "$id"
    dscl . -create "/Groups/$name" Password '*'
    dscl . -create "/Users/$name"
    dscl . -create "/Users/$name" UniqueID "$id"
    dscl . -create "/Users/$name" PrimaryGroupID "$id"
    dscl . -create "/Users/$name" RealName "$realname"
    dscl . -create "/Users/$name" UserShell /usr/bin/false
    dscl . -create "/Users/$name" NFSHomeDirectory /var/empty
    dscl . -create "/Users/$name" Password '*'
    dscl . -create "/Users/$name" IsHidden 1
}

create _edrnet "EDR network daemon"
create _edrinspect "EDR file inspector"
