#!/bin/bash

mkdir -p afl

make clean

make AFL=1

tmux new-window "afl-fuzz -i examples -o afl -M core0 ./blove @@ -o fuzz-out-0"

for (( i = 1; i <= $(( $(nproc) - 1 )); i++ )); do
    tmux new-window "afl-fuzz -i examples -o afl -S core$i ./blove @@ -o fuzz-out-$i"
done

