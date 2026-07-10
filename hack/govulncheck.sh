#!/usr/bin/env bash

# Copyright 2026 ko Build Authors All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Wrapper around govulncheck that allows selectively ignoring known findings.
# govulncheck itself has no built-in ignore/suppress support
# (https://go.dev/issue/61211); this filters JSON output instead.
#
# Add GO- IDs to IGNORE_VULNS below to nack findings that are accepted for
# this codebase.

set -o errexit
set -o nounset
set -o pipefail

# Space-separated list of vulnerability IDs to ignore.
# GO-2026-5932: golang.org/x/crypto/openpgp is unmaintained by design with no
# fix; it is a transitive dependency and a known recurring finding.
IGNORE_VULNS="GO-2026-5932"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${PROJECT_ROOT}"

if ! command -v govulncheck >/dev/null; then
  echo "govulncheck is not installed" >&2
  exit 1
fi

if ! command -v jq >/dev/null; then
  echo "jq is required to filter ignored vulnerabilities" >&2
  exit 1
fi

# Show the normal human-readable report for CI logs. govulncheck exits
# non-zero when it finds vulnerabilities; we decide pass/fail from JSON.
set +o errexit
govulncheck ./...
text_status=$?
set -o errexit

if [[ "${text_status}" -eq 0 ]]; then
  exit 0
fi

json="$(govulncheck -format json ./...)"

# Collect unique OSV IDs for called (symbol-level) findings, excluding ignores.
# Imported-only findings have an empty function in the first trace frame and
# are not treated as failures by default govulncheck text mode either.
# See: https://github.com/golang/vuln/blob/master/internal/scan/template.go
remaining="$(jq -rcs --arg ignores "${IGNORE_VULNS}" '
  ($ignores | split(" ") | map(select(length > 0))) as $ignore
  | [
      .[]
      | .finding // empty
      | select((.trace[0].function // "") != "")
      | .osv
    ]
  | unique
  | map(select(. as $id | $ignore | index($id) | not))
  | .[]
' <<<"${json}")"

if [[ -z "${remaining}" ]]; then
  echo
  echo "govulncheck reported vulnerabilities, but all are in the ignore list (${IGNORE_VULNS})."
  exit 0
fi

echo
echo "govulncheck found vulnerabilities that are not ignored:"
echo "${remaining}"
exit 1
