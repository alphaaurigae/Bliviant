#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

DEBUG=0

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/shared/config.sh"

LOGFILE="$WORKDIR/log/run_encrypt.debug.log"

ENCRYPT_ARCHIVE_DEFAULT=1

CREATE_SCRIPT="$WORKDIR/create/create_proof.sh"
DESCRIPTION_FILE="$INPUT_DIR/README_PROOF.txt"

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
	echo "Checking requirements..."
	echo "WORKDIR=$WORKDIR"
	echo "REPO_NAME=$REPO_NAME"
	echo "CREATE_SCRIPT=$CREATE_SCRIPT"
	echo "PRIVKEY_PATH=$PRIVKEY_PATH"

	if [ ! -x "$CREATE_SCRIPT" ]; then
		printf "%s%s%s%s\n" "${BOLD}${RED}" "ERROR:" "${RESET}" " create_proof.sh not executable at $CREATE_SCRIPT" >&2
		exit 1
	fi

	if [ ! -f "$PRIVKEY_PATH" ]; then
		printf "%s%s%s%s\n" "${BOLD}${RED}" "ERROR:" "${RESET}" " private key not found at $PRIVKEY_PATH" >&2
		exit 2
	fi

	if [ ! -d "$REPO_PATH" ]; then
		printf "%s%s%s%s\n" "${BOLD}${RED}" "ERROR:" "${RESET}" " repository directory not found at $REPO_PATH" >&2
		exit 3
	fi

	echo "All requirements passed."
}

build_args() {
	ARGS=("$WORKDIR" "$REPO_PATH")

	if [ -n "$DESCRIPTION_FILE" ] && [ -f "$DESCRIPTION_FILE" ]; then
		ARGS+=("$DESCRIPTION_FILE")
	fi

	if [ "$ENCRYPT_ARCHIVE_DEFAULT" -eq 1 ]; then
		ARGS+=("--encrypt-archive")
	fi

	printf "%s%s%s%s\n" "${BOLD}${WHITE}" "Built arguments:" "${RESET}" " ${ARGS[*]}"
}

run_create() {
	exec "$CREATE_SCRIPT" "${ARGS[@]}"
}

main() {
	setup_debug
	trap fail_trap ERR

	check_requirements
	build_args
	run_create
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
	main "$@"
fi
