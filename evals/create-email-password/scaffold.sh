#!/usr/bin/env bash
# Seeds the run workspace with the express-starter fixture.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
cp -R "$here/../_fixtures/express-starter/." .
