#!/usr/bin/env bash
# Seeds the run workspace with the verification-app fixture.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
cp -R "$here/../_fixtures/verification-app/." .
