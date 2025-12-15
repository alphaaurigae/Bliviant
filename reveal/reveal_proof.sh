#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../shared/config.sh"

PROOF_NAME="${REPO_NAME}_proof"
OUTDIR_DEFAULT="$OUTPUT_DIR/$PROOF_NAME"

OPENSSL_RSA_OPTS=(-pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256)

usage() {
	cat <<EOF
Usage: $0 PROOF_DIR [--output-dir PATH] [--key PATH]
Example:
$0 proof_bling --output-dir ./bling_proof --key ~/.ssh/sshkfd1
EOF
	exit 2
}

parse_args() {
	PROOF_DIR="$1"
	shift
	OUTDIR="$OUTDIR_DEFAULT"
	while [ "$#" -gt 0 ]; do
		case "$1" in
			--output-dir) OUTDIR="$2"; shift 2 ;;
			--key) PRIVKEY_PATH="$2"; shift 2 ;;
			*) shift ;;
		esac
	done
}

setup_tmp() {
	TMPDIR="$(mktemp -d)"
	trap cleanup EXIT
}

cleanup() {
	rm -rf "$TMPDIR"
}


retry_openssl() {
	local MAX_TRIES=3
	local TRY=1
	while true; do

	printf "%s%s%s%s\n" "${BOLD}${WHITE}" "NOTICE:" "${RESET}" " Running OpenSSL: $@"
	if "$@"; then
		return 0
	fi

	printf "%s%s%s%s\n" "${BOLD}${RED}" "ERROR:" "${RESET}" " OpenSSL operation failed (attempt $TRY/$MAX_TRIES)" >&2

	((TRY++))
	if [ "$TRY" -gt "$MAX_TRIES" ]; then
		printf "%s%s%s%s\n" "${BOLD}${RED}" "ERROR:" "${RESET}" " OpenSSL failed after $MAX_TRIES attempts" >&2
		return 1
	fi
	sleep 1
	done
}

decrypt_description() {
	DESCRIPTION_ENC_B64="$(ls "$PROOF_DIR"/description.enc.b64 2>/dev/null | head -n1 || true)"
	DESCRIPTION_ENC="$(ls "$PROOF_DIR"/description.enc 2>/dev/null | head -n1 || true)"

	if [ -n "$DESCRIPTION_ENC_B64" ]; then
		DESCRIPTION_DECODER="$TMPDIR/description.enc"
		base64 -d "$DESCRIPTION_ENC_B64" > "$DESCRIPTION_DECODER"
		retry_openssl openssl pkeyutl -decrypt -inkey "$PRIVKEY_PATH" \
		"${OPENSSL_RSA_OPTS[@]}" \
		-in "$DESCRIPTION_DECODER" \
		-out "$OUTDIR/README_PROOF.txt"
	rm -f "$DESCRIPTION_DECODER"
	elif [ -n "$DESCRIPTION_ENC" ]; then
		retry_openssl openssl pkeyutl -decrypt -inkey "$PRIVKEY_PATH" \
		"${OPENSSL_RSA_OPTS[@]}" \
		-in "$DESCRIPTION_ENC" \
		-out "$OUTDIR/README_PROOF.txt"
	fi
}

decrypt_archive() {
	: "${ARCHIVE_ENC:?ARCHIVE_ENC not set}"
	openssl pkeyutl -decrypt -inkey "$PRIVKEY_PATH" \
		"${OPENSSL_RSA_OPTS[@]}" \
		-in "$PROOF_DIR/sym.key.enc" \
		-out "$TMPDIR/sym.key"

	ARCHIVE_BASE="$(basename "$ARCHIVE_ENC" .enc)"
	IV_FILE="$PROOF_DIR/${ARCHIVE_BASE}.iv"
	HMAC_FILE="$PROOF_DIR/${ARCHIVE_BASE}.hmac"

	[ -f "$IV_FILE" ] && [ -f "$HMAC_FILE" ] || exit 6

	IV="$(cat "$IV_FILE")"
	AES_KEY_HEX="$(xxd -p -c 256 "$TMPDIR/sym.key" | cut -c1-64)"
	MAC_KEY_HEX="$(xxd -p -c 256 "$TMPDIR/sym.key" | cut -c65-128)"

	openssl dgst -sha256 -mac HMAC -macopt hexkey:$MAC_KEY_HEX -binary "$ARCHIVE_ENC" > "$TMPDIR/computed.hmac"
	cmp -s "$TMPDIR/computed.hmac" "$HMAC_FILE" || exit 7

	ARCHIVE_NAME="$(grep '^archive_name=' "$PROOF_DIR/PROOF_MANIFEST.txt" | cut -d= -f2)"

	openssl enc -d -aes-256-ctr -K "$AES_KEY_HEX" -iv "$IV" \
		-in "$ARCHIVE_ENC" -out "$TMPDIR/$ARCHIVE_NAME" -nosalt

	shred -u "$TMPDIR/sym.key"
	ARCHIVE_TAR="$TMPDIR/$ARCHIVE_NAME"
}

verify_hashes() {
	MANIFEST="$PROOF_DIR/PROOF_MANIFEST.txt"

	MANIFEST_ENC="$(grep '^archive_encrypted=' "$MANIFEST" | cut -d= -f2)"

	if [ "$MANIFEST_ENC" = "1" ] && [ -z "$ARCHIVE_ENC" ]; then
		exit 10
	fi

	if [ "$MANIFEST_ENC" = "0" ] && [ -n "$ARCHIVE_ENC" ]; then
		exit 11
	fi

	ARCHIVE_NAME="$(grep '^archive_name=' "$MANIFEST" | cut -d= -f2)"
	ACTUAL_NAME="$(basename "$ARCHIVE_TAR")"

	if [ "$ARCHIVE_NAME" != "$ACTUAL_NAME" ]; then
		exit 12
	fi

	EXPECTED_HASH="$(grep '^archive_sha256=' "$MANIFEST" | cut -d= -f2)"
	COMPUTED_HASH="$(sha256sum "$ARCHIVE_TAR" | cut -d' ' -f1)"

	[ "$EXPECTED_HASH" = "$COMPUTED_HASH" ] || exit 9
}


extract_archive() {
	tar --numeric-owner -xf "$ARCHIVE_TAR" -C "$OUTDIR"
}

verify_filelist() {
	FILELIST="$(find "$OUTDIR" -name "*_filelist.sha256" | head -n1 || true)"
	[ -n "$FILELIST" ] && (cd "$(dirname "$FILELIST")" && sha256sum -c "$(basename "$FILELIST")")
}


verify_tsa_timestamp() {
	[ ! -f "$PROOF_DIR/PROOF_MANIFEST.txt.tsr" ] && return 0

	openssl ts -verify \
		-data "$PROOF_DIR/PROOF_MANIFEST.txt" \
		-in "$PROOF_DIR/PROOF_MANIFEST.txt.tsr" \
		-CAfile /etc/ssl/certs/ca-certificates.crt || {
			echo "TSA timestamp verification failed" >&2
			exit 15
		}
}

verify_manifest_signature() {
	[ -f "$PUBKEY_PATH" ] || { echo "ERROR: public key not found at $PUBKEY_PATH" >&2; exit 20; }
	openssl dgst -sha256 \
		-verify "$PUBKEY_PATH" \
		-signature "$PROOF_DIR/PROOF_MANIFEST.txt.sig" \
		"$PROOF_DIR/PROOF_MANIFEST.txt"
}

archive_file_handling() {
	ARCHIVE_TAR="$(ls "$PROOF_DIR"/*.tar 2>/dev/null | head -n1 || true)"
	ARCHIVE_ENC_B64="$(ls "$PROOF_DIR"/*.tar.enc.b64 2>/dev/null | head -n1 || true)"
	ARCHIVE_ENC=""

	if [ -n "$ARCHIVE_ENC_B64" ]; then
		ARCHIVE_ENC="$TMPDIR/$(basename "$ARCHIVE_ENC_B64" .b64)"
		base64 -d "$ARCHIVE_ENC_B64" > "$ARCHIVE_ENC"
	else
		ARCHIVE_ENC="$(ls "$PROOF_DIR"/*.tar.enc 2>/dev/null | head -n1 || true)"
	fi
}

[ "$#" -lt 1 ] && usage

parse_args "$@"
mkdir -p "$OUTDIR"
setup_tmp

PUBKEY_PATH="$PROOF_DIR/proof_public.pem"

archive_file_handling
decrypt_description
if [ -n "$ARCHIVE_ENC" ]; then
	decrypt_archive
else
	ARCHIVE_TAR="$(ls "$PROOF_DIR"/*.tar | head -n1)"
fi
verify_manifest_signature
verify_tsa_timestamp
verify_hashes
extract_archive
verify_filelist

echo "Restore complete: $OUTDIR"
exit 0