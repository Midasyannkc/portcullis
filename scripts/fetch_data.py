"""Download the real data this project uses and write data/raw/MANIFEST.json (url, bytes, sha256).
Nothing here is modified after download. Run once; the files are committed."""
import hashlib
import json
import os
import sys

import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW = os.path.join(ROOT, "data/raw")
GH = "https://raw.githubusercontent.com"
manifest = {}


def get(url, dest, binary=False):
    r = requests.get(url, timeout=60)
    if r.status_code != 200:
        print("skip", r.status_code, url)
        return False
    path = os.path.join(RAW, dest)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, "wb").write(r.content)
    manifest[dest] = {"url": url, "bytes": len(r.content), "sha256": hashlib.sha256(r.content).hexdigest()}
    return True


get(f"{GH}/cisagov/kev-data/main/known_exploited_vulnerabilities.json", "kev.json")

workflows = {
    "actions-checkout-test.yml": "actions/checkout/main/.github/workflows/test.yml",
    "nodejs-node-test-linux.yml": "nodejs/node/main/.github/workflows/test-linux.yml",
    "facebook-react-runtime.yml": "facebook/react/main/.github/workflows/runtime_build_and_test.yml",
    "pallets-flask-tests.yaml": "pallets/flask/main/.github/workflows/tests.yaml",
    "psf-requests-tests.yml": "psf/requests/main/.github/workflows/run-tests.yml",
    "expressjs-express-ci.yml": "expressjs/express/master/.github/workflows/ci.yml",
    "tokio-ci.yml": "tokio-rs/tokio/master/.github/workflows/ci.yml",
    "serde-ci.yml": "serde-rs/serde/master/.github/workflows/ci.yml",
    "mystenlabs-sui-rust.yml": "MystenLabs/sui/main/.github/workflows/rust.yml",
    "mystenlabs-sui-external.yml": "MystenLabs/sui/main/.github/workflows/external.yml",
    "vercel-nextjs-build.yml": "vercel/next.js/canary/.github/workflows/build_and_test.yml",
    "django-tests.yml": "django/django/main/.github/workflows/tests.yml",
    "tj-actions-changed-files-test.yml": "tj-actions/changed-files/main/.github/workflows/test.yml",
}
for name, p in workflows.items():
    get(f"{GH}/{p}", f"workflows/{name}")

move = ["coin", "balance", "transfer", "vec_map", "kiosk/kiosk"]
for m in move:
    get(f"{GH}/MystenLabs/sui/main/crates/sui-framework/packages/sui-framework/sources/{m}.move", f"move/{m.replace('/', '_')}.move")

for ghsa, yms in {"GHSA-mrrh-fwg8-r2c3": ["2025/03"], "GHSA-4x49-vf9v-38px": ["2025/09"], "GHSA-qj3p-xc97-xw74": ["2025/09"],
                  "GHSA-5fvm-p68v-5wmh": ["2025/09", "2025/10"], "GHSA-53mq-f4w3-f7qv": ["2025/09", "2025/10", "2025/11"],
                  "GHSA-m662-56rj-8fmm": ["2025/09", "2025/10"], "GHSA-jwq7-6j4r-2f92": ["2025/09", "2025/10"]}.items():
    for ym in yms:
        if get(f"{GH}/github/advisory-database/main/advisories/github-reviewed/{ym}/{ghsa}/{ghsa}.json", f"advisories/{ghsa}.json"):
            break

for rid, crate in [("RUSTSEC-2020-0071", "time"), ("RUSTSEC-2023-0071", "rsa"), ("RUSTSEC-2022-0093", "ed25519-dalek"), ("RUSTSEC-2021-0124", "tokio")]:
    get(f"{GH}/rustsec/advisory-db/main/crates/{crate}/{rid}.md", f"rustsec/{rid}.md")

get("https://registry.npmjs.org/-/npm/v1/keys", "npm/registry_keys.json")
packages = ["left-pad", "ms", "debug", "chalk", "escape-string-regexp", "ansi-styles", "supports-color", "is-number", "lodash", "express", "react", "axios",
            "esbuild", "core-js", "husky", "puppeteer", "sharp", "node-gyp", "typescript", "eslint", "prettier", "webpack", "uuid", "minimist", "semver",
            "commander", "yargs", "moment", "dayjs", "bluebird", "request", "async", "underscore", "jquery", "vue", "next", "zod", "chai", "mocha", "jest"]
for p in packages:
    get(f"https://registry.npmjs.org/{p}/latest", f"npm/latest/{p}.json")
for p in ["left-pad", "ms", "debug", "chalk", "escape-string-regexp", "ansi-styles", "supports-color", "is-number", "semver", "uuid"]:
    meta = json.load(open(os.path.join(RAW, f"npm/latest/{p}.json")))
    get(meta["dist"]["tarball"], f"npm/tarballs/{os.path.basename(meta['dist']['tarball'])}")

json.dump(manifest, open(os.path.join(RAW, "MANIFEST.json"), "w"), indent=1, sort_keys=True)
print(len(manifest), "files")
