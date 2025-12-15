#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

# STATIC - do not change!
WORKDIR="$ROOT_DIR"
INPUT_DIR="$WORKDIR/input"
OUTPUT_DIR="$WORKDIR/output"
################################

README_MESSAGE="None of your business :)" # Text for the readme prepare_readme() { -> create_proof.sh

SSH_DIR="$HOME/.ssh"
PRIVKEY_PATH="$SSH_DIR/sshkfd1"
REPO_NAME="bling" # Directory name for input directory in `input/$REPO_NAME`.
REPO_PATH="$INPUT_DIR/$REPO_NAME" # STATIC - do not change!

RSA_BITS="16384" # Define RSA bits for RSA encryption ... 16384 bec why not ... in a hurry? try 4096 ... .

TAR_MTIME='UTC 2025-01-01' # Cosmetic, timestamp with TSA `in timestamp_manifest() {`
EXCLUDE_PATTERNS=(.git build bin) # Exclude something in `input/$REPO_NAME` input dir.
ENABLE_TSA_TIMESTAMP=1 # Do not change unless you dont want a TSA timestamp.


################################
# COLOR
BOLD=$(tput bold)
RESET=$(tput sgr0)
# Regular colors
BLACK=$(tput setaf 0)
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
BLUE=$(tput setaf 4)
MAGENTA=$(tput setaf 5)
CYAN=$(tput setaf 6)
WHITE=$(tput setaf 7)

# Bright colors
BRIGHT_BLACK=$(tput setaf 8)
BRIGHT_RED=$(tput setaf 9)
BRIGHT_GREEN=$(tput setaf 10)
BRIGHT_YELLOW=$(tput setaf 11)
BRIGHT_BLUE=$(tput setaf 12)
BRIGHT_MAGENTA=$(tput setaf 13)
BRIGHT_CYAN=$(tput setaf 14)
BRIGHT_WHITE=$(tput setaf 15)