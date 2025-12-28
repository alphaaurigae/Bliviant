#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

DEBUG=0

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/shared/config.sh"

LOGFILE="$WORKDIR/log/run_decrypt.debug.log"

PROOF_NAME="${REPO_NAME}_proof"
PROOFS_DIR="$OUTPUT_DIR"
PROOF_ARCHIVE="$PROOFS_DIR/${PROOF_NAME}.tar.bz2"

REVEAL_OUTPUT_DIR="$OUTPUT_DIR/${PROOF_NAME}"

REVEAL_SCRIPT="$WORKDIR/reveal/reveal_proof.sh"

TMP_PROOF_DIR="$(mktemp -d)"

source "$SCRIPT_DIR/shared/proof_verify.sh"

setup_debug() {
	if [ "${DEBUG:-0}" -eq 1 ]; then
		mkdir -p "$(dirname "$LOGFILE")"
		exec > >(tee -a "$LOGFILE") 2> >(tee -a "$LOGFILE" >&2)
	fi
}

fail_trap() {
	printf "%s%s%s%s\n" "${BOLD}${RED}" "ERROR:" "${RESET}" " line=$LINENO cmd=$BASH_COMMAND exit=$?" >&2
}

check_requirements() {
	printf "%s%s%s%s\n" "${BOLD}${WHITE}" "INFO:" "${RESET}" " Checking requirements..."
	printf "%s\n" " PROOF_ARCHIVE=$PROOF_ARCHIVE"
	printf "%s\n" " REVEAL_SCRIPT=$REVEAL_SCRIPT"
	printf "%s\n" " PRIVKEY_PATH=$PRIVKEY_PATH"
	printf "%s\n" " WORKDIR=$WORKDIR"
	printf "%s\n" " REVEAL_OUTPUT_DIR=$REVEAL_OUTPUT_DIR"

	[ -f "$PROOF_ARCHIVE" ] || {
		printf "%s%s%s%s\n" "${BOLD}${RED}" "ERROR:" "${RESET}" " Proof archive not found at $PROOF_ARCHIVE" >&2
		exit 1
	}
	[ -x "$REVEAL_SCRIPT" ] || {
		printf "%s%s%s%s\n" "${BOLD}${RED}" "ERROR:" "${RESET}" " reveal_proof.sh not executable at $REVEAL_SCRIPT" >&2
		exit 2
	}
	[ -f "$PRIVKEY_PATH" ] || {
		printf "%s%s%s%s\n" "${BOLD}${RED}" "ERROR:" "${RESET}" " Private key not found at $PRIVKEY_PATH" >&2
		exit 3
	}
	[ -d "$WORKDIR" ] || {
		printf "%s%s%s%s\n" "${BOLD}${RED}" "ERROR:" "${RESET}" " Work directory not found at $WORKDIR" >&2
		exit 4
	}

	mkdir -p "$REVEAL_OUTPUT_DIR"
	printf "%s%s%s%s\n" "${BOLD}${GREEN}" "SUCCESS:" "${RESET}" " All requirements passed."
}

extract_proof() {
	tar -xjf "$PROOF_ARCHIVE" -C "$TMP_PROOF_DIR"
	PROOF_DIR="$TMP_PROOF_DIR/$(ls -1 "$TMP_PROOF_DIR" | head -n1)"
	echo "$PROOF_DIR"
}

verify_post_state() {
	local out="$1"
	local proof="$out/.proof"

	[ -f "$out/README_PROOF.txt" ] || exit 20
	[ -d "$out/bling" ] || exit 21
	ls "$out"/*_filelist.sha256 >/dev/null 2>&1 || exit 22

	[ -d "$proof" ] || exit 30
	[ -f "$proof/PROOF_MANIFEST.txt" ] || exit 31
	[ -f "$proof/PROOF_MANIFEST.txt.sig" ] || exit 32
	[ -f "$proof/proof_public.pem" ] || exit 33
	ls "$proof"/*.tar.enc >/dev/null 2>&1 || exit 34
	ls "$proof"/*.iv >/dev/null 2>&1 || exit 35
	ls "$proof"/*.hmac >/dev/null 2>&1 || exit 36
}

run_reveal() {
	local PROOF_DIR="$1"
	"$REVEAL_SCRIPT" "$PROOF_DIR" "--output-dir" "$REVEAL_OUTPUT_DIR" "--key" "$PRIVKEY_PATH"
}

setup_debug
trap fail_trap ERR

check_requirements

PROOF_DIR="$(extract_proof)"

mkdir -p "$REVEAL_OUTPUT_DIR/.proof"
cp -a "$PROOF_DIR"/. "$REVEAL_OUTPUT_DIR/.proof/"

run_reveal "$PROOF_DIR"
verify_post_state "$REVEAL_OUTPUT_DIR"

PROOF_VERIFY_ORIG="$REVEAL_OUTPUT_DIR/.proof/PROOF_VERIFY.txt"
PROOF_VERIFY_NEW="$REVEAL_OUTPUT_DIR/.proof/PROOF_VERIFY_NEW.txt"
generate_proof_verify "$REVEAL_OUTPUT_DIR/.proof" "$PROOF_VERIFY_NEW"
printf "%s%s%s%s\n" "${BOLD}${WHITE}" "INFO:" "${RESET}" " Comparing original proof vs decrypted/revealed proof:"
compare_proofs "$PROOF_VERIFY_ORIG" "$PROOF_VERIFY_NEW" || printf "%s%s%s%s\n" "${BOLD}${RED}" "ERROR:" "${RESET}" " Mismatch detected!"
