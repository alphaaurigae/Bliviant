#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
compare_proofs() {
    local orig="$1"
    local new="$2"
    if cmp -s "$orig" "$new"; then
	printf "%s%s%s%s\n" "${BOLD}${GREEN}" "SUCCESS:" "${RESET}" " Proofs match."
        return 0
    else
	printf "%s%s%s%s\n" "${BOLD}${RED}" "ERROR:" "${RESET}" " Proofs do not match."
        return 1
    fi
}
generate_proof_verify() {
	local proof_dir="$1"
	local out_file="$2"

	local manifest="$proof_dir/PROOF_MANIFEST.txt"
	local sig="$proof_dir/PROOF_MANIFEST.txt.sig"
	local pub="$proof_dir/proof_public.pem"

	archive_name=$(grep '^archive_name=' "$manifest" | cut -d= -f2)
	archive_sha256=$(grep '^archive_sha256=' "$manifest" | cut -d= -f2)
	archive_encrypted=$(grep '^archive_encrypted=' "$manifest" | cut -d= -f2)
	description_sha256=$(grep '^description_sha256=' "$manifest" | cut -d= -f2)

	manifest_sha256=$(sha256sum "$manifest" | cut -d' ' -f1)
	manifest_sig_sha256=$(sha256sum "$sig" | cut -d' ' -f1)
	pubkey_sha256=$(sha256sum "$pub" | cut -d' ' -f1)

	if [ -f "$proof_dir/PROOF_MANIFEST.txt.tsr" ]; then
		tsa_present=1
		tsa_sha256=$(sha256sum "$proof_dir/PROOF_MANIFEST.txt.tsr" | cut -d' ' -f1)
	else
		tsa_present=0
		tsa_sha256=none
	fi

	cat > "$out_file" <<EOF
archive_name=$archive_name
archive_sha256=$archive_sha256
archive_encrypted=$archive_encrypted
description_sha256=$description_sha256
manifest_sha256=$manifest_sha256
manifest_signature_sha256=$manifest_sig_sha256
tsa_present=$tsa_present
tsa_token_sha256=$tsa_sha256
public_key_sha256=$pubkey_sha256
EOF
}