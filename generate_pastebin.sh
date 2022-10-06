#! /usr/bin/env bash

tail -n +1 *.c *.h *.py go.sh benchmark.sh > pastebin.txt

# Make sure the resulting file is anonymized
grep -i nimrod pastebin.txt
grep -i eyal pastebin.txt
