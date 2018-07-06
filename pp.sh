#!/usr/bin/env bash

# useful utility for processing hex strings and packet captures to byte
# array data that can be used in golang.

DATA=$(echo $* | sed -e 's/0x[0-9]*://g' -e 's/ //g' | fold -w2 | tr '\n' ' ')
echo $DATA | sed -e 's/ /, 0x/g' -e 's/^/0x/' | fold -s
