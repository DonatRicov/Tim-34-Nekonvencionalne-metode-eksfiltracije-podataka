#/usr/bin/env bash
set -e

if [ "$#" -ne 2 ]; then
	echo "Uporaba: $0 sifrirana.png izlazna.bin"
	exit 1
fi

SIFRIRANA="$1"
IZLAZ="$2"

TEMPORARY=$(mktemp)

stegano-lsb reveal -i "$SIFRIRANA" -o "$TEMPORARY"

base64 --decode "$TEMPORARY" > "$IZLAZ"

rm "$TEMPORARY"

echo "Skriveni sadrzaj u datoteci '$SIFRIRANA' spremljen je u '$IZLAZ'"
