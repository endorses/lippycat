#!/bin/sh
# Inspect ordinary, unstripped builds and prove the same predicate detects LI.
set -eu

verify_dir=$(mktemp -d "${TMPDIR:-/tmp}/lippycat-verify-no-li.XXXXXX")
trap 'rm -rf "$verify_dir"' EXIT HUP INT TERM

"${GO:-go}" build ${GOFLAGS:--trimpath} -tags all -ldflags "${LDFLAGS:-}" -o "$verify_dir/non-li" .
"${GO:-go}" build ${GOFLAGS:--trimpath} -tags all,li -ldflags "${LDFLAGS:-}" -o "$verify_dir/li" .
# Keep inspection separate from matching: a failed nm must never look absent.
"${GO:-go}" tool nm "$verify_dir/non-li" > "$verify_dir/non-li.symbols"
"${GO:-go}" tool nm "$verify_dir/li" > "$verify_dir/li.symbols"

for symbol in \
    'github.com/endorses/lippycat/internal/pkg/li.NewManager' \
    'github.com/endorses/lippycat/internal/pkg/li.(*CallCorrelator).ResolveAsync' \
    'github.com/endorses/lippycat/internal/pkg/li/delivery.NewClient'
do
    # Matching complete names avoids confusing shared types with implementation.
    if ! awk -v symbol="$symbol" '$3 == symbol { found = 1 } END { exit !found }' "$verify_dir/li.symbols"; then
        echo "ERROR: LI reference build lacks representative implementation symbol" >&2
        exit 1
    fi
    if awk -v symbol="$symbol" '$3 == symbol { found = 1 } END { exit !found }' "$verify_dir/non-li.symbols"; then
        echo "ERROR: LI implementation found in non-LI build" >&2
        exit 1
    else
        inspect_status=$?
        if [ "$inspect_status" -ne 1 ]; then
            echo "ERROR: non-LI symbol inspection failed" >&2
            exit "$inspect_status"
        fi
    fi
done
echo "OK: non-LI implementation exclusion verified against LI reference build"
