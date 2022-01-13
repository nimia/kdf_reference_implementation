#! /usr/bin/env bash

gcc -O3 -std=c11 benchmark.c reference_implementation.c -lssl -lcrypto -ldl -o benchmark || exit 1
./benchmark

