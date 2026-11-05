# Python CloakBrowser boundary

Browser-assisted QR login uses the optional Python CloakBrowser SDK.

## Selected implementation

- One browser launcher: `xhs_cli.browser.browser_page`.
- Optional `browser` extra uses `cloakbrowser>=0.7,<0.8`; the lock fixes the resolved version.
- Use the Python API `cloakbrowser.launch(headless=False, humanize=True)` exactly.
- Returned objects are Python Playwright Browser/Context/Page objects. There is no
  custom Node.js worker, stdio RPC bridge, CDP adapter or alternate browser backend.
- Use a new isolated context, never a personal browser profile. Close context and
  browser on normal completion, errors and cancellation. The SDK owns its driver.
- Call the SDK directly regardless of DISPLAY/Wayland presence or SSH use. No
  display preflight, desktop-environment injection, automatic Xvfb, desktop
  discovery or headless fallback exists. Actual startup is decided by the SDK/OS;
  SDK errors remain safe diagnostics, not an application-imposed permission gate.
- Existing multi-browser cookie extraction reads local data; it does not launch a browser.

## Installation and credentials

From this checkout use `uv sync --extra browser`, then the SDK's `cloakbrowser login`
and `cloakbrowser install` setup. A pre-existing license can be configured through
`CLOAKBROWSER_LICENSE_KEY`; a managed binary override is `CLOAKBROWSER_BINARY_PATH`.
That override is a CloakBrowser binary, not ordinary system Chromium.

The SDK owns license resolution and its managed download/update behavior. Calling
launch may fetch a browser or update managed state; no "no download" guarantee is
made here. Prepare the vendor runtime before unattended use. This integration does
not bundle a browser, register an account, accept a license or create a service on
installation/import. Vendor licenses and redistribution terms remain separate.

`qrcode_login` consumes browser events registered before navigation, renders one QR,
exports allowlisted cookies and verifies the actual account through the API client.
Its `QrLoginResult` does not write credential files. The CLI renders QR/status on
stderr and atomically saves only a verified result. An embedding host owns its own
storage and permissions. Phone confirmation alone never proves authentication.

License keys, response bodies, QR secrets and session cookies must not appear in
normal diagnostics. `humanize=True` activates vendor interaction adjustments, not
new permissions or a guarantee against verification/moderation. Do not blindly
retry CAPTCHA, unknown platform effects or account mismatches.

## API scope

`qrcode_login` now returns `QrLoginResult(cookies, user)` instead of a cookie
mapping and no longer writes files. Embedders should read `result.cookies` and
own storage; the CLI persists only after account verification. Legacy direct-HTTP
QR endpoint helpers and fallback login are removed. General API operations and
reading cookies from existing browser profiles remain unchanged.

## Primary references

- Python launcher: https://github.com/CloakHQ/CloakBrowser/blob/main/cloakbrowser/browser.py
- SDK package: https://pypi.org/project/cloakbrowser/
- Binary management: https://github.com/CloakHQ/CloakBrowser/blob/main/cloakbrowser/download.py
- Vendor licensing: https://github.com/CloakHQ/CloakBrowser/blob/main/BINARY-LICENSE.md

Current tests verify fixed launch options, lazy optional imports, SDK dispatch
with no display environment and resource cleanup. The installed-SDK contract test replaces external
binary/license/Playwright IO and verifies the visible Chromium call and actual
humanization hook dispatch. These tests are not a real CloakBrowser GUI launch,
license activation, Xiaohongshu login or anti-detection benchmark.

## Test scope

The deterministic tests mock network/browser IO. They do not download browser
binaries, activate licenses, log into a real account or validate anti-detection
claims. The installed-SDK contract test exercises launch/humanization dispatch
with Playwright and vendor binary/license IO replaced.
