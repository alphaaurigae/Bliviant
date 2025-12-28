#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../shared/config.sh"

source "$SCRIPT_DIR/../shared/proof_verify.sh"

DEBUG=0

OPENSSL_PASSIN_OPTS=()
if [ -n "${PRIVKEY_PASS:-}" ]; then
	OPENSSL_PASSIN_OPTS=(-passin "pass:${PRIVKEY_PASS}")
fi

print_usage() {
	cat <<EOF
Usage: $0 WORKDIR SECRET_REPO_DIR [DESCRIPTION_FILE] [--encrypt-archive]
Example: $0 "/home/a/desktop" "bling" README_PROOF.txt --encrypt-archive
EOF
	exit 2
}

validate_args() {
	if [ "$#" -lt 2 ]; then
		print_usage
	fi
}

parse_args() {
	WORKDIR=$1
	REPO_PATH=$2
	REPO="$(basename "$REPO_PATH")"
	shift 2
	DESC_FILE=""
	ENCRYPT_ARCHIVE=0

	while [ "$#" -gt 0 ]; do
		case "$1" in
			--encrypt-archive)
				ENCRYPT_ARCHIVE=1
				shift
				;;
			*)
				if [ -z "$DESC_FILE" ]; then DESC_FILE=$1; fi
				shift
				;;
		esac
	done
}

check_paths() {
	if [ ! -d "$REPO_PATH" ]; then
		printf "%s%s%s%s\n" "${BOLD}${RED}" "ERROR:" "${RESET}" " repository directory not found: $REPO_PATH" >&2

		exit 3
	fi

	if [ ! -f "$PRIVKEY_PATH" ]; then
		printf "%s%s%s%s\n" "${BOLD}${RED}" "ERROR:" "${RESET}" " private key not found: $PRIVKEY_PATH" >&2
		exit 4
	fi
}

prepare_tmp_and_outdir() {
	TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
	OUTDIR="$OUTPUT_DIR/proof_${REPO}_${TIMESTAMP}"
	mkdir -p "$OUTDIR"
	ARCHIVE_NAME="${REPO}.tar"
	ENC_NAME="${ARCHIVE_NAME}.enc"
	IV_NAME="${ARCHIVE_NAME}.iv"
	HMAC_NAME="${ARCHIVE_NAME}.hmac"

	TMPDIR=$(mktemp -d)
	trap 'rm -rf "$TMPDIR"' EXIT
}

create_filelist() {
	find "$REPO_PATH" -type f -printf "%P\0" | sort -z | xargs -0 -I{} sha256sum "$REPO_PATH/{}" >"$TMPDIR/${REPO}_filelist.sha256"
}

create_archive() {
	tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="$TAR_MTIME" \
		$(for p in "${EXCLUDE_PATTERNS[@]}"; do printf -- "--exclude=%s " "$p"; done) \
		-cf "$OUTDIR/$ARCHIVE_NAME" \
		-C "$(dirname "$REPO_PATH")" "$(basename "$REPO_PATH")" \
		-C "$TMPDIR" "$(basename "${REPO}_filelist.sha256")"
}

compute_archive_hash() {
	sha256sum "$OUTDIR/$ARCHIVE_NAME" | tee "$OUTDIR/$ARCHIVE_NAME.sha256" >/dev/null
}

prepare_readme() {
	if [ -n "$DESC_FILE" ] && [ -f "$DESC_FILE" ]; then
		cp "$DESC_FILE" "$OUTDIR/README_PROOF.txt"
	else
		cat >"$OUTDIR/README_PROOF.txt" <<EOF
$README_MESSAGE
Repository: $REPO
Archive: $ARCHIVE_NAME
Archive SHA256: $(cut -d' ' -f1 "$OUTDIR/$ARCHIVE_NAME.sha256")
Created: $TIMESTAMP (UTC)
EOF
	fi
}

generate_keys() {
	openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:$RSA_BITS -out "$OUTDIR/proof_private.pem"
	openssl pkey -in "$OUTDIR/proof_private.pem" -pubout -out "$OUTDIR/proof_public.pem"
}

derive_pub_for_enc() {
	if [ -f "$SSH_DIR/$(basename "$PRIVKEY_PATH").pub" ]; then
		ssh-keygen -f "$SSH_DIR/$(basename "$PRIVKEY_PATH").pub" -e -m PEM >"$TMPDIR/sshpub.pem"
		PUB_FOR_ENC="$TMPDIR/sshpub.pem"
	else
		openssl pkey "${OPENSSL_PASSIN_OPTS[@]}" -in "$PRIVKEY_PATH" -pubout -out "$TMPDIR/sshpub.pem" 2>/dev/null || true
		if [ -f "$TMPDIR/sshpub.pem" ]; then
			PUB_FOR_ENC="$TMPDIR/sshpub.pem"
		else
			printf "%s%s%s%s\n" "${BOLD}${RED}" "ERROR:" "${RESET}" " cannot derive public key from $PRIVKEY_PATH" >&2
			exit 5
		fi
	fi
}

retry_openssl() {
	local MAX_TRIES=3
	local TRY=1
	local CMD=("$@")

	while true; do

		if "${CMD[@]}"; then
			return 0
		fi

		printf "%s%s%s%s\n" "${BOLD}${RED}" "ERROR:" "${RESET}" " OpenSSL operation failed (attempt $TRY/$MAX_TRIES)" >&2
		((TRY++))

		if [ "$TRY" -gt "$MAX_TRIES" ]; then
			printf "%s%s%s%s\n" "${BOLD}${RED}" "ERROR:" "${RESET}" " OpenSSL failed repeatedly — possible wrong passphrase or key issue. Aborting." >&2
			return 1
		fi

		printf "%s%s%s%s\n" "${YELLOW}${RED}" "WARNING:" "${RESET}" " Please enter the passphrase again." >&2
	done
}

encrypt_description() {
	retry_openssl openssl pkeyutl -encrypt -pubin -inkey "$PUB_FOR_ENC" -pkeyopt rsa_padding_mode:oaep \
		-pkeyopt rsa_oaep_md:sha256 -in "$OUTDIR/README_PROOF.txt" -out "$OUTDIR/description.enc"

	base64 -w0 "$OUTDIR/description.enc" >"$OUTDIR/description.enc.b64"
}

verify_description() {
	retry_openssl openssl "${OPENSSL_PASSIN_OPTS[@]}" pkeyutl -decrypt -inkey "$PRIVKEY_PATH" -pkeyopt rsa_padding_mode:oaep \
		-pkeyopt rsa_oaep_md:sha256 -in "$OUTDIR/description.enc" -out "$TMPDIR/README_PROOF.dec"

	cmp "$OUTDIR/README_PROOF.txt" "$TMPDIR/README_PROOF.dec"
	if [ $? -eq 0 ] && [ -z "${DESC_FILE:-}" ] && [ -f "$OUTDIR/README_PROOF.txt" ]; then
		shred -u "$OUTDIR/README_PROOF.txt" 2>/dev/null || rm -f "$OUTDIR/README_PROOF.txt"
	fi
}

encrypt_archive_if_requested() {
	if [ "$ENCRYPT_ARCHIVE" -eq 1 ]; then
		openssl rand -out "$TMPDIR/sym.key" 64
		IV=$(openssl rand -hex 16)
		printf '%s\n' "$IV" >"$OUTDIR/$IV_NAME"

		AES_KEY_HEX=$(xxd -p -c 256 "$TMPDIR/sym.key" | cut -c1-64)
		MAC_KEY_HEX=$(xxd -p -c 256 "$TMPDIR/sym.key" | cut -c65-128)

		openssl enc -aes-256-ctr -K "$AES_KEY_HEX" -iv "$IV" -in "$OUTDIR/$ARCHIVE_NAME" -out "$OUTDIR/$ENC_NAME" -nosalt
		openssl dgst -sha256 -mac HMAC -macopt hexkey:$MAC_KEY_HEX -binary "$OUTDIR/$ENC_NAME" >"$OUTDIR/$HMAC_NAME"
		base64 -w0 "$OUTDIR/$HMAC_NAME" >"$OUTDIR/$HMAC_NAME.b64"

		retry_openssl openssl pkeyutl -encrypt -pubin -inkey "$PUB_FOR_ENC" -pkeyopt rsa_padding_mode:oaep \
			-pkeyopt rsa_oaep_md:sha256 -in "$TMPDIR/sym.key" -out "$OUTDIR/sym.key.enc"

		base64 -w0 "$OUTDIR/$ENC_NAME" >"$OUTDIR/$ENC_NAME.b64"
		base64 -w0 "$OUTDIR/sym.key.enc" >"$OUTDIR/sym.key.enc.b64"

		shred -u "$TMPDIR/sym.key" 2>/dev/null || rm -f "$TMPDIR/sym.key"
		shred -u "$OUTDIR/$ARCHIVE_NAME" 2>/dev/null || rm -f "$OUTDIR/$ARCHIVE_NAME"
	fi
}

cleanup_sensitive() {
	shred -u "$TMPDIR/README_PROOF.dec" || true
	shred -u "$OUTDIR/proof_private.pem" || true
}

finalize_and_package() {
	FINAL_PROOF="$OUTPUT_DIR/${REPO}_proof.tar.bz2"
	tar cjf "$FINAL_PROOF" -C "$OUTPUT_DIR" "$(basename "$OUTDIR")" \
		$([ -f "$OUTDIR/PROOF_MANIFEST.txt.tsr" ] && printf '%s\n' "$(basename "$OUTDIR")/PROOF_MANIFEST.txt.tsr")
	rm -rf "$OUTDIR"
	printf "%s%s%s%s\n" "${BOLD}${WHITE}" "NOTICE:" "${RESET}" " Final proof archive: $FINAL_PROOF"
	exit 0
}

sign_manifest() {
	openssl dgst -sha256 \
		-sign "$OUTDIR/proof_private.pem" \
		-out "$OUTDIR/PROOF_MANIFEST.txt.sig" \
		"$OUTDIR/PROOF_MANIFEST.txt"
}

create_manifest() {
	cat >"$OUTDIR/PROOF_MANIFEST.txt" <<EOF
archive_name=$ARCHIVE_NAME
archive_sha256=$(cut -d' ' -f1 "$OUTDIR/$ARCHIVE_NAME.sha256")
archive_encrypted=$ENCRYPT_ARCHIVE
description_sha256=$(sha256sum "$OUTDIR/README_PROOF.txt" | cut -d' ' -f1)
created_utc=$TIMESTAMP
EOF
}

timestamp_manifest() {
	[ "$ENABLE_TSA_TIMESTAMP" -ne 1 ] && return 0
	: "${OUTDIR:?OUTDIR is not set}"

	TSA_URL="http://timestamp.digicert.com"
	TSQ="$OUTDIR/PROOF_MANIFEST.txt.tsq"
	TSR="$OUTDIR/PROOF_MANIFEST.txt.tsr"
	CHAIN_UNTRUSTED="$OUTDIR/tsa_chain_untrusted.pem"
	TMP_PKCS7="$OUTDIR/tsa_pkcs7.pem"

	mkdir -p "$OUTDIR"

	openssl ts -query -data "$OUTDIR/PROOF_MANIFEST.txt" -cert -sha256 -out "$TSQ" \
		2>"$OUTDIR/ts_query.log" || return 6

	curl -sS -H "Content-Type: application/timestamp-query" \
		--data-binary @"$TSQ" "$TSA_URL" -o "$TSR" || return 7

	[ ! -s "$TSR" ] && return 8

	openssl ts -reply -in "$TSR" -token_out -out "$OUTDIR/tsa_token.der"
	openssl pkcs7 -inform DER -in "$OUTDIR/tsa_token.der" -print_certs \
		-out "$CHAIN_UNTRUSTED"

	openssl ts -verify \
		-data "$OUTDIR/PROOF_MANIFEST.txt" \
		-in "$TSR" \
		-CAfile /etc/ssl/certs/ca-certificates.crt \
		-untrusted "$CHAIN_UNTRUSTED" \
		-text || return 9

	printf "%s%s%s%s\n\n" "${BOLD}${WHITE}" "NOTICE:" "${RESET}" \
		" TSA timestamp using $TSA_URL
	 Timestamp verified successfully.
	 The TSA certificate is not a CA certificate.
	 Timestamping authorities issue certificates only for signing timestamps, not for acting as a root CA.
	 To manually verify, you can run:"

	printf "   %s%s%s%s\n\n" "${BOLD}" "\$ [EXAMPLE] openssl ts -verify -data \"OUTDIR/PROOF_MANIFEST.txt\" -in \"OUTDIR/PROOF_MANIFEST.txt.tsr\" -CAfile /etc/ssl/certs/ca-certificates.crt -untrusted \"OUTDIR/tsa_chain_untrusted.pem\"" "${RESET}" ""

	# cp -f "$OUTDIR/tsa_token.der" "$TSR"
}

main() {
	validate_args "$@"
	parse_args "$@"

	[ "$DEBUG" -eq 1 ] && set -x

	check_paths
	prepare_tmp_and_outdir
	create_filelist
	create_archive
	compute_archive_hash
	prepare_readme
	create_manifest
	generate_keys
	sign_manifest
	timestamp_manifest
	derive_pub_for_enc
	encrypt_description
	verify_description
	generate_proof_verify "$OUTDIR" "$OUTDIR/PROOF_VERIFY.txt"
	encrypt_archive_if_requested
	cleanup_sensitive
	finalize_and_package
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
	main "$@"
fi
