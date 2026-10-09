#!/usr/bin/env bash
# Seeds the run workspace with the clean-reset-app fixture.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
cp -R "$here/../_fixtures/clean-reset-app/." .
