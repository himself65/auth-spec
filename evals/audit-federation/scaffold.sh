#!/usr/bin/env bash
# Seeds the run workspace with the federation-app fixture.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
cp -R "$here/../_fixtures/federation-app/." .
