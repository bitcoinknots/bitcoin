#!/usr/bin/env bash
# Start an isolated, offline DCBM GUI preview using only repository-local data.
set -euo pipefail

gui_args=()
if (( $# == 1 )) && [[ "$1" == --smoke-test ]]; then
    export QT_QPA_PLATFORM=offscreen
    gui_args+=(-stopafterblockimport=1)
elif (( $# != 0 )); then
    printf 'Usage: %s [--smoke-test] (creates a fresh isolated regtest directory)\n' "$0" >&2
    exit 1
fi
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
gui_binary="$repo_dir/build/bin/bitcoin-qt"
if [[ ! -x "$gui_binary" ]]; then
    printf 'Build bitcoin-qt first; see doc/dynamic-cbm-gui.md\n' >&2
    exit 1
fi
data_dir="$(mktemp -d "$repo_dir/build/dcbm-gui.XXXXXXXX")"
export XDG_CONFIG_HOME="$data_dir/config"
export XDG_CACHE_HOME="$data_dir/cache"
export XDG_DATA_HOME="$data_dir/share"
mkdir -p "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME" "$XDG_DATA_HOME"
if (( ${#gui_args[@]} != 0 )); then
    export XDG_RUNTIME_DIR="$data_dir/runtime"
    mkdir -m 700 "$XDG_RUNTIME_DIR"
fi
printf 'Isolated DCBM GUI data: %s\n' "$data_dir"
exec "$gui_binary" \
    -regtest -datadir="$data_dir" -settings=0 -disablewallet=1 \
    -connect=0 -dnsseed=0 -fixedseeds=0 -listen=0 -listenonion=0 \
    -discover=0 -upnp=0 -natpmp=0 -softwareexpiry=0 \
    -testcoinbasematuritylong=2:2:122 \
    -testcoinbasematuritylongexpiry=1819756800 \
    -testdynamiccbm=1 -testdynamiccbminitial=150 \
    -mocktime=1819760400 "${gui_args[@]}"
