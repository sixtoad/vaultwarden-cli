#!/usr/bin/env bash
# Reassemble both architectures and compare the committed test-time machine code.
set -euo pipefail
fixture_root="$(cd -- "$(dirname -- "$0")/.." && pwd)"
assembly_tmp="$(mktemp -d)"
trap 'rm -rf -- "$assembly_tmp"' EXIT
for architecture in x86_64 aarch64; do
    for fixture in protected-exit protected-output; do
        clang -target "${architecture}-linux-gnu" -c \
            "$fixture_root/tests/fixtures/${fixture}.S" -o "$assembly_tmp/fixture.o"
        llvm-objcopy -O binary --only-section=.text "$assembly_tmp/fixture.o" "$assembly_tmp/fixture.bin"
        cmp "$assembly_tmp/fixture.bin" "$fixture_root/tests/fixtures/${fixture}-${architecture}.bin"
        # Raw embedded code must have no unresolved text relocations.
        relocations="$(llvm-readelf --relocations "$assembly_tmp/fixture.o")"
        if [[ "$relocations" == *R_* ]]; then
            echo "unresolved fixture relocation: ${fixture}/${architecture}" >&2
            exit 1
        fi
        echo "verified ${fixture}/${architecture}"
    done
    clang -target "${architecture}-linux-gnu" -ffreestanding -fno-stack-protector \
        -fno-builtin -O2 -Wall -Wextra -Werror -c \
        "$fixture_root/tests/fixtures/protected-tree.c" -o "$assembly_tmp/tree-${architecture}.o"
done
