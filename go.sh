#! /usr/bin/env bash

gcc -fsanitize=address -std=c11 kdf_test.c reference_implementation.c -lssl -lcrypto -ldl -o kdf_test || exit 1
./kdf_test

