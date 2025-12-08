#!/usr/bin/env bash
set -e

if [ "$#" -ne 3 ]; then
	echo "Uporaba: $0 ulaz.png tajniFile.bin izlaz.png"
	exit 1
fi

ULAZ="$1"
TAJNIFILE="$2"
IZLAZ="$3"

TEMPORARY=$(mktemp)

base64 "$TAJNIFILE" > "$TEMPORARY"

stegano-lsb hide -i "$ULAZ" -f "$TEMPORARY" -o "$IZLAZ"

rm "$TEMPORARY"

echo "Datoteka '$TAJNIFILE' sakrivena je u '$IZLAZ'"
