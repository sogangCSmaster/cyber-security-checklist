#!/usr/bin/env bash
set -euo pipefail
"$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../scaffold.sh" clean-app
printf '\nYou will recieve an email when your export is ready.\n' >> README.md
