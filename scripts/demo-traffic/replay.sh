#!/usr/bin/env bash
# Replay synthetic packets on a private veth pair and open lippycat's live TUI.
set -euo pipefail

if (( $# > 3 )); then
    printf 'Usage: %s [capture.pcap] [lippycat-binary] [packets-per-second]\n' "$0" >&2
    exit 2
fi
capture=${1:-testdata/pcaps/demo-mixed.pcap}
binary=${2:-./lc}
rate=${3:-30}
if (( EUID != 0 )); then
    printf 'Run this helper with sudo to create the virtual link and capture packets.\n' >&2
    exit 1
fi
for dependency in ip tcpreplay realpath; do
    if ! command -v "$dependency" >/dev/null; then
        printf 'Missing prerequisite: %s\n' "$dependency" >&2
        exit 1
    fi
done
if [[ ! -f "$capture" || ! -r "$capture" || ! -x "$binary" ]]; then
    printf 'Expected a readable PCAP and executable lippycat binary: %s, %s\n' "$capture" "$binary" >&2
    exit 1
fi
if [[ ! "$rate" =~ ^[1-9][0-9]*$ ]]; then
    printf 'Packet rate must be a positive integer.\n' >&2
    exit 2
fi
capture=$(realpath -- "$capture")
binary=$(realpath -- "$binary")
capture_if="lcd$$"
replay_if="lcr$$"
link_created=0
replay_pid=''
session_dir=''

cleanup() {
    local result=$? replay_result
    trap - EXIT INT TERM
    if [[ -n "$replay_pid" ]]; then
        if kill -0 "$replay_pid" 2>/dev/null; then
            if ! kill "$replay_pid"; then
                printf 'Failed to stop replay process %s.\n' "$replay_pid" >&2
                result=1
            fi
        fi
        if wait "$replay_pid"; then
            :
        else
            replay_result=$?
            if (( replay_result != 130 && replay_result != 143 )); then
                printf 'tcpreplay exited with status %s:\n' "$replay_result" >&2
                cat "$session_dir/replay.log" >&2
                result=1
            fi
        fi
    fi
    if (( link_created )); then
        if ! ip link delete "$capture_if"; then
            printf 'Failed to remove virtual link %s.\n' "$capture_if" >&2
            result=1
        fi
    fi
    if [[ -n "$session_dir" ]]; then
        if ! rm -rf -- "$session_dir"; then
            printf 'Failed to remove demo session directory %s.\n' "$session_dir" >&2
            result=1
        fi
    fi
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

session_dir=$(mktemp -d "${TMPDIR:-/tmp}/lippycat-demo-replay.XXXXXX")
printf '{}\n' > "$session_dir/config.yaml"
ip link add "$capture_if" type veth peer name "$replay_if"
link_created=1
for interface in "$capture_if" "$replay_if"; do
    # Disable automatic IPv6 link-local chatter on this temporary interface.
    setting="/proc/sys/net/ipv6/conf/$interface/disable_ipv6"
    if [[ -e "$setting" ]]; then
        printf '1\n' > "$setting"
    fi
    ip link set "$interface" up
done
printf 'Synthetic traffic: %s → %s at %s packets/s. Quit the TUI with q.\n' "$replay_if" "$capture_if" "$rate"
tcpreplay --loop=0 --pps="$rate" --intf1="$replay_if" "$capture" > "$session_dir/replay.log" 2>&1 &
replay_pid=$!
sleep 0.2
if ! kill -0 "$replay_pid" 2>/dev/null; then
    printf 'Replay failed before capture started.\n' >&2
    exit 1
fi
"$binary" --config "$session_dir/config.yaml" watch live -i "$capture_if" -p
