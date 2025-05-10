#!/usr/bin/env bash

# if not running as root, re-exec under sudo
if [[ $EUID -ne 0 ]]; then
  exec sudo bash "$0" "$@"
fi

for dbname in leveldb lmdb rocksdb wiredtiger; do
  echo "Initiating $dbname"
  python3 ./run.py --db-names "$dbname" -wl Init
  rm -rf bench/ebpf bench/results
  for workload in WriteOnly ReadOnly ReadHeavy ReadMostly Balanced RangeScan Remove; do
    rm -rf "results-single-threaded/$dbname/$workload"
    mkdir -p "results-single-threaded/$dbname/$workload"
    # Timing pass
    python3 ./run.py --db-names "$dbname" --threads 1 -wl $workload -dp --with-ebpf
    mv bench/ebpf/snapshots "results-single-threaded/$dbname/$workload/ebpf-snapshots"
    mv bench/results/without_caches/cores_1/disks_1/$dbname/bench.json "results-single-threaded/$dbname/$workload/"
    # Memory pass
    python3 ./run.py --db-names "$dbname" --threads 1 -wl $workload -dp --with-ebpf --with-ebpf-memory
    mv bench/ebpf/snapshots "results-single-threaded/$dbname/$workload/ebpf-memory-snapshots"
    # Cleanup
    rm -rf bench/ebpf bench/results
  done
done
