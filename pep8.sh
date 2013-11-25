#!/bin/sh

PEP8=$(which pep8)

if [ -z "$PEP8" ]; then
echo "Couldn't find the pep8 binary $PEP8"
    exit 1
fi

if [ -z "$1" ]; then
echo "[INFO] Scanning all python files from $(pwd) downwards"
    find . -name '*.py' | sed -e '/venv/d' | xargs "$PEP8" --max-line-length=120
elif [ -d "$1" ]; then
echo "[INFO] Scanning all python files from $1 downwards"
    find "$1" -name '*.py' | sed -e '/venv/d' | xargs "$PEP8" --max-line-length=120
elif [ -f "$1" ]; then
echo "[INFO] Scanning individual python file $1"
    "$PEP8" "$1" --max-line-length=120
else
echo "Bad argument '$1'."
    exit 1
fi
