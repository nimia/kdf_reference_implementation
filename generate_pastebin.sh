#! /usr/bin/env bash

echo "Compiled with OpenSSL 1.1.1" > pastebin.txt
tail -n +1 *.c *.h *.py go.sh benchmark.sh >> pastebin.txt

# Make sure the resulting file is anonymized
grep -i nimrod pastebin.txt
grep -i eyal pastebin.txt
