#!/bin/bash

# Note: Need to delete prev db before start next benchmark with different workload
# sudo rm -rf ./tmp/

#
# 100MB benchmarks
#
sudo rm -rf ./tmp/
sudo ./build_release/bin/_ucsb_bench -db unumdb -c ./bench/configs/unumdb/config_100MB.json -w ./bench/workloads/100MB.json
sudo ./build_release/bin/_ucsb_bench -db rocksdb -c ./bench/configs/rocksdb/options.ini -w ./bench/workloads/100MB.json
sudo ./build_release/bin/_ucsb_bench -db leveldb -c ./bench/configs/leveldb/config.json -w ./bench/workloads/100MB.json
sudo ./build_release/bin/_ucsb_bench -db wiredtiger -c ./bench/configs/wiredtiger/config.json -w ./bench/workloads/100MB.json
sudo ./build_release/bin/_ucsb_bench -db lmdb -c ./bench/configs/lmdb/config.json -w ./bench/workloads/100MB.json

#
# 1GB benchmarks
#
# sudo rm -rf ./tmp/
# sudo ./build_release/bin/_ucsb_bench -db unumdb -c ./bench/configs/unumdb/config.json -w ./bench/workloads/1GB.json
# sudo ./build_release/bin/_ucsb_bench -db rocksdb -c ./bench/configs/rocksdb/options.ini -w ./bench/workloads/1GB.json
# sudo ./build_release/bin/_ucsb_bench -db leveldb -c ./bench/configs/leveldb/config.json -w ./bench/workloads/1GB.json
# sudo ./build_release/bin/_ucsb_bench -db wiredtiger -c ./bench/configs/wiredtiger/config.json -w ./bench/workloads/1GB.json
# sudo ./build_release/bin/_ucsb_bench -db lmdb -c ./bench/configs/lmdb/config.json -w ./bench/workloads/1GB.json

#
# 10GB benchmarks
#
# sudo rm -rf ./tmp/
# sudo ./build_release/bin/_ucsb_bench -db unumdb -c ./bench/configs/unumdb/config.json -w ./bench/workloads/10GB.json
# sudo ./build_release/bin/_ucsb_bench -db rocksdb -c ./bench/configs/rocksdb/options.ini -w ./bench/workloads/10GB.json
# sudo ./build_release/bin/_ucsb_bench -db leveldb -c ./bench/configs/leveldb/config.json -w ./bench/workloads/10GB.json
# sudo ./build_release/bin/_ucsb_bench -db wiredtiger -c ./bench/configs/wiredtiger/config.json -w ./bench/workloads/10GB.json
# sudo ./build_release/bin/_ucsb_bench -db lmdb -c ./bench/configs/lmdb/config.json -w ./bench/workloads/10GB.json

#
# 100GB benchmarks
#
# sudo rm -rf ./tmp/
# sudo ./build_release/bin/_ucsb_bench -db unumdb -c ./bench/configs/unumdb/config.json -w ./bench/workloads/100GB.json
# sudo ./build_release/bin/_ucsb_bench -db rocksdb -c ./bench/configs/rocksdb/options.ini -w ./bench/workloads/100GB.json
# sudo ./build_release/bin/_ucsb_bench -db leveldb -c ./bench/configs/leveldb/config.json -w ./bench/workloads/100GB.json
# sudo ./build_release/bin/_ucsb_bench -db wiredtiger -c ./bench/configs/wiredtiger/config.json -w ./bench/workloads/100GB.json
# sudo ./build_release/bin/_ucsb_bench -db lmdb -c ./bench/configs/lmdb/config.json -w ./bench/workloads/100GB.json

#
# 1TB benchmarks
#
# sudo rm -rf ./tmp/
# sudo ./build_release/bin/_ucsb_bench -db unumdb -c ./bench/configs/unumdb/config.json -w ./bench/workloads/1TB.json
# sudo ./build_release/bin/_ucsb_bench -db rocksdb -c ./bench/configs/rocksdb/options.ini -w ./bench/workloads/1TB.json
# sudo ./build_release/bin/_ucsb_bench -db leveldb -c ./bench/configs/leveldb/config.json -w ./bench/workloads/1TB.json
# sudo ./build_release/bin/_ucsb_bench -db wiredtiger -c ./bench/configs/wiredtiger/config.json -w ./bench/workloads/1TB.json
# sudo ./build_release/bin/_ucsb_bench -db lmdb -c ./bench/configs/lmdb/config.json -w ./bench/workloads/1TB.json
