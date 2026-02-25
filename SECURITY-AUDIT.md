# Security Audit Report: free-games-claimer

**Audit Date:** 2026-02-25
**Repository:** benjaminmue/free-games-claimer (fork of vogler/free-games-claimer)
**Version:** 1.4.0
**Auditor:** Automated security audit (Claude)

---

## A) Executive Summary

**Overall Risk Level: MEDIUM**

This repository is a Node.js browser-automation tool that uses Playwright to claim free games
from Epic Games Store, Amazon Prime Gaming, GOG, and Unreal Engine Marketplace. It stores
credentials as plaintext environment variables, generates TOTP codes locally via `otplib`,
and uses `apprise` for notifications.

**Key positive findings:**
- No evidence of malicious code, backdoors, or credential exfiltration.
- No telemetry, analytics, or tracking SDKs.
- TOTP seeds (`EG_OTPKEY`, `PG_OTPKEY`) are used only locally to generate OTP codes; neither the seed nor the generated code is logged or transmitted to any service other than the target login provider's web form.
- All network destinations are legitimate game stores and their APIs.
- `.gitignore` properly excludes `data/`, `*.env`, and `node_modules/`.

**Key risk findings:**
- Credentials and OTP keys are stored as plaintext environment variables with no encryption.
- Debug mode (`DEBUG=1`) dumps browser cookies to disk as JSON and logs network requests including URLs with session tokens.
- VNC in Docker defaults to **no password**, exposing the browser session.
- Docker container runs as **root**.
- Notification messages (`NOTIFY`) may include redemption codes sent to third-party webhook services.
- `exec()` in `src/version.js` takes hardcoded commands (no injection risk) but uses shell execution.
- Some dependencies use caret (`^`) version ranges rather than pinned versions.

---

## B) Findings Table

| ID | Severity | Category | File(s) | Evidence | Why It Matters | Exploit Scenario | Recommended Fix |
|----|----------|----------|---------|----------|---------------|-----------------|-----------------|
| F01 | Medium | Secrets Handling | `src/config.js:32-46` | `eg_password: process.env.EG_PASSWORD \|\| process.env.PASSWORD` | All credentials stored as plaintext env vars. No encryption at rest. | An attacker with read access to the process environment (e.g., via `/proc/PID/environ` on Linux, or container inspection) can extract all passwords and OTP keys. | Use a secrets manager (Docker secrets, HashiCorp Vault) or at minimum encrypt the config file at rest. |
| F02 | Low | Secrets Handling | `src/config.js:4` | `dotenv.config({ path: 'data/config.env' })` | Config file is loaded from a predictable path. If the data volume is shared or leaked, all secrets are exposed. | Volume mount misconfiguration exposes config.env on host filesystem. | Ensure `data/config.env` has mode `0600`. Document the risk in README. |
| F03 | Medium | Debug Logging | `epic-games.js:322` | `if (cfg.debug) writeFileSync(path.resolve(cfg.dir.browser, 'cookies.json'), JSON.stringify(await context.cookies()));` | In debug mode, all browser cookies (including session tokens) are written to disk as plaintext JSON. | An attacker with filesystem access can steal session cookies and impersonate the user on Epic Games. | Remove or gate this behind a separate `DEBUG_COOKIES` flag. Add a warning log. Ensure the file is deleted after use. |
| F04 | Medium | Debug Logging | `unrealengine.js:204` | `if (cfg.debug) writeFileSync(path.resolve(cfg.dir.browser, 'cookies.json'), JSON.stringify(await context.cookies()));` | Same cookie dump issue as F03, for Unreal Engine. | Same as F03. | Same as F03. |
| F05 | Low | Debug Logging | `epic-games.js:58-63` | `if (cfg.debug_network) { page.on('request', request => ... console.log('>>', request.method(), request.url())); page.on('response', response => ... console.log('<<', response.status(), response.url())); }` | Debug network mode logs all request/response URLs which may contain session tokens and auth parameters in query strings. | Container logs or terminal history could expose auth tokens. | Filter sensitive query parameters from URLs before logging. |
| F06 | Medium | Docker Security | `Dockerfile` (entire file) | No `USER` directive; defaults to root. | Container processes run as root. If an attacker escapes the browser sandbox, they have root privileges in the container. | Browser exploit → container root → potential host escape depending on Docker config. | Add `RUN useradd -m fgcuser` and `USER fgcuser` after installing dependencies. |
| F07 | High | Docker Security | `docker-entrypoint.sh:43-50` | `if [ -z "$VNC_PASSWORD" ]; then pw="-nopw"` | VNC server starts with **no password** by default. Anyone on the network can connect and see/control the browser session containing logged-in game accounts. | Network attacker connects to port 5900, takes over browser session, changes account passwords. | Change default to require a password. At minimum, bind VNC to localhost and only expose via noVNC. Document this prominently. |
| F08 | Low | Docker Security | `docker-entrypoint.sh:41` | `Xvfb $DISPLAY -ac -screen 0` | `-ac` disables X11 host-based access control. | Any process in the container can access the display. Minimal risk since the container is single-purpose. | Remove `-ac` or keep it but document why it's used. |
| F09 | Medium | Docker Security | `docker-compose.yml:9` | `- "6080:6080"` | noVNC port is exposed to all interfaces by default, not just localhost. | Any machine on the same network can access the browser session. | Change to `"127.0.0.1:6080:6080"` or document the risk. |
| F10 | Medium | Notification Data Leak | `prime-gaming.js:338` | `notify_game.status = '<a href="${redeem_url}">${redeem_action}</a> ${code} on ${store}';` | Redemption codes are included in notification messages sent to third-party services (Telegram, Discord, etc.). | If the notification channel is compromised or publicly accessible, game codes can be stolen. | Allow users to opt out of including codes in notifications, or redact them. |
| F11 | Low | Notification Data Leak | `src/util.js:121` | `if (cfg.debug) console.debug('apprise ${args.map(a => "'${a}'").join(' ')}');` | In debug mode, the full apprise command (including the NOTIFY URL which may contain tokens/passwords for webhook services) is logged. | Terminal/log history exposes notification service credentials. | Redact the NOTIFY URL in debug output. |
| F12 | Low | Code Execution | `src/version.js:7` | `exec(cmd, (error, stdout, stderr) => { ... })` | Uses `child_process.exec()` which spawns a shell. Commands are hardcoded strings (`'git rev-parse HEAD'`, `'git show -s --format=%cD'`), so no injection risk exists today. | If a future developer changes this to include user input, it becomes a shell injection vector. | Use `execFile` (already used in `util.js` for apprise) instead of `exec`. |
| F13 | Low | Supply Chain | `package.json:22-31` | `"playwright-firefox": "^1.52.0"`, all deps use caret ranges | Caret ranges allow automatic minor/patch upgrades. A compromised npm package update could affect this project. | Supply-chain attack via malicious update to any dependency. | Pin exact versions in `package.json` or use `package-lock.json` integrity checks. Run `npm audit` regularly. |
| F14 | Low | Supply Chain | `package.json:27` | `"fingerprint-injector": "^2.1.66"` | The fingerprint-injector and related fingerprint-generator packages (from Apify) add browser fingerprint spoofing. These are complex packages with broad browser access. | Malicious update could inject code into the browser context. | Pin version exactly. Review updates before upgrading. |
| F15 | Low | CI/CD | `.github/workflows/sonar.yml:39` | `uses: sonarsource/sonarcloud-github-action@master` | Uses `@master` branch reference instead of a pinned SHA or version tag. | If the SonarCloud action is compromised, it could exfiltrate `SONAR_TOKEN` and `GITHUB_TOKEN`. | Pin to a specific SHA: `uses: sonarsource/sonarcloud-github-action@<sha>`. |
| F16 | Low | Data Persistence | `data/` directory | Browser profiles, JSON databases, screenshots, HAR recordings all stored in `data/`. | Browser profile contains session cookies, cached credentials, and history. Screenshots may show account information. HAR files record all HTTP traffic. | If the `data/` volume is shared or backed up insecurely, all session data is exposed. | Document that `data/` is sensitive. Add encryption at rest guidance. Periodically clean old screenshots and HAR files. |
| F17 | Info | Documentation | `README.md:125` | `Beware that storing passwords and OTP keys as clear text may be a security risk. Use a unique/generated password!` | The README acknowledges the risk but offers no mitigation beyond "use a unique password". | Users may store their primary credentials in plaintext. | Provide concrete guidance: use throwaway accounts, Docker secrets, or an encrypted config. |
| F18 | Info | Documentation | `README.md:114` | `NOTIFY='mailto://myemail:mypass@gmail.com'` | Example shows email credentials in a NOTIFY URL in documentation. | Users may copy-paste and expose their email password. | Use a placeholder like `NOTIFY='tgram://bottoken/ChatID'` and warn about credential URLs. |
| F19 | Low | Session Security | All main scripts | `firefox.launchPersistentContext(cfg.dir.browser, ...)` | All scripts share the same browser profile directory. Sessions, cookies, and cache from one service are accessible to all scripts. | A compromised session on one store could potentially affect cross-domain cookies or cached data. | Consider using separate browser profile directories per service, or document the shared-profile behavior. |
| F20 | Low | Network | `docker-entrypoint.sh:47` | `pw="-passwd $VNC_PASSWORD"` | VNC_PASSWORD is passed as a command-line argument, visible in `/proc/PID/cmdline`. | Any user/process in the container can read the VNC password from the process list. | Use x11vnc's password file option (`-rfbauth`) instead of `-passwd`. |

---

## C) Secret-Flow Traces

### EG_EMAIL / EG_PASSWORD (Epic Games credentials)

```
Environment / data/config.env
  → dotenv.config()                         [src/config.js:4]
  → process.env.EG_EMAIL / EG_PASSWORD      [src/config.js:32-33]
  → cfg.eg_email / cfg.eg_password          [src/config.js:32-33]
  → epic-games.js:87   console.info('Using email and password from environment.')  ← NO secret value logged
  → epic-games.js:98   email = cfg.eg_email
  → epic-games.js:109  page.fill('#email', email)  ← SENT: to Epic Games login form via Playwright
  → epic-games.js:111  password = cfg.eg_password
  → epic-games.js:114  page.fill('#password', password)  ← SENT: to Epic Games login form via Playwright
  ✓ NOT logged, NOT stored to disk, NOT sent to notifications
  ✓ Only destination: https://www.epicgames.com/id/login (TLS)
```

### EG_OTPKEY (Epic Games TOTP seed)

```
Environment / data/config.env
  → dotenv.config()                         [src/config.js:4]
  → process.env.EG_OTPKEY                   [src/config.js:34]
  → cfg.eg_otpkey                           [src/config.js:34]
  → epic-games.js:126  authenticator.generate(cfg.eg_otpkey)  ← LOCAL computation only
  → epic-games.js:126  otp = <6-digit code>  ← generated OTP stored in local variable
  → epic-games.js:127  page.locator('input[name="code-input-0"]').pressSequentially(otp.toString())
                        ← SENT: OTP code to Epic Games MFA form via Playwright
  ✓ TOTP seed: NEVER logged, NEVER stored, NEVER sent anywhere
  ✓ Generated OTP: NEVER logged, NEVER sent to notifications
  ✓ Only destination: Epic Games MFA form (TLS)

  Same pattern in unrealengine.js:76-77 (uses same EG_OTPKEY for Epic Games auth)
```

### PG_OTPKEY (Prime Gaming / Amazon TOTP seed)

```
Environment / data/config.env
  → dotenv.config()                         [src/config.js:4]
  → process.env.PG_OTPKEY                   [src/config.js:39]
  → cfg.pg_otpkey                           [src/config.js:39]
  → prime-gaming.js:72  authenticator.generate(cfg.pg_otpkey)  ← LOCAL computation only
  → prime-gaming.js:72  otp = <6-digit code>
  → prime-gaming.js:73  page.locator('input[name=otpCode]').pressSequentially(otp.toString())
                         ← SENT: OTP code to Amazon MFA form via Playwright
  ✓ TOTP seed: NEVER logged, NEVER stored, NEVER sent anywhere
  ✓ Generated OTP: NEVER logged, NEVER sent to notifications
  ✓ Only destination: Amazon MFA form (TLS)
```

### EG_PARENTALPIN

```
Environment / data/config.env
  → cfg.eg_parentalpin                      [src/config.js:35]
  → epic-games.js:249-253  if (!cfg.eg_parentalpin) console.error(...)  ← only logs ABSENCE
  → epic-games.js:253  iframe.locator('input.payment-pin-code__input').first().pressSequentially(cfg.eg_parentalpin)
                        ← SENT: to Epic Games purchase iframe (TLS)
  ✓ PIN value: NEVER logged, NEVER sent to notifications
```

### PG_EMAIL / PG_PASSWORD (Prime Gaming / Amazon credentials)

```
  → cfg.pg_email / cfg.pg_password          [src/config.js:37-38]
  → prime-gaming.js:50  console.info('Using email and password from environment.')  ← NO secret value
  → prime-gaming.js:55  page.fill('[name=email]', email)  ← SENT: to Amazon login (TLS)
  → prime-gaming.js:57  page.fill('[name=password]', password)  ← SENT: to Amazon login (TLS)
  ✓ NOT logged, NOT stored, NOT sent to notifications
```

### GOG_EMAIL / GOG_PASSWORD

```
  → cfg.gog_email / cfg.gog_password        [src/config.js:41-42]
  → gog.js:56  console.info('Using email and password from environment.')  ← NO secret value
  → gog.js:62  iframe.locator('#login_username').fill(email)  ← SENT: to GOG login iframe (TLS)
  → gog.js:63  iframe.locator('#login_password').fill(password)  ← SENT: to GOG login iframe (TLS)
  ✓ NOT logged, NOT stored, NOT sent to notifications
```

### LG_EMAIL (Legacy Games email)

```
  → cfg.lg_email                            [src/config.js:50]
  → prime-gaming.js:317  page2.fill('[name=email]', cfg.lg_email)  ← SENT: to Legacy Games form (TLS)
  → prime-gaming.js:318  page2.fill('[name=email_validate]', cfg.lg_email)
  ✓ NOT logged, NOT sent to notifications
```

### NOTIFY (Apprise notification URL)

```
  → cfg.notify                              [src/config.js:23]
  → src/util.js:114  if (!cfg.notify) return resolve()
  → src/util.js:119  args = [cfg.notify, '-i', 'html', '-b', ...]
  → src/util.js:121  if (cfg.debug) console.debug(...)  ← WARNING: logs full NOTIFY URL in debug mode (F11)
  → src/util.js:122  execFile('apprise', args, ...)  ← SENT: to apprise CLI (local process)
  ⚠ NOTIFY URL may contain webhook tokens (Telegram bot tokens, Discord webhook URLs, email passwords)
  ⚠ In debug mode, the URL is logged to console
```

### VNC_PASSWORD

```
  → docker-entrypoint.sh:43-50
  → Passed as command-line argument to x11vnc: `-passwd $VNC_PASSWORD`
  ⚠ Visible in /proc/PID/cmdline (F20)
  ⚠ Defaults to no password if not set (F07)
```

---

## D) Network Map

| # | Destination | Protocol | File(s) | What Is Sent | Credentials Included? |
|---|-------------|----------|---------|--------------|-----------------------|
| 1 | `store.epicgames.com` | HTTPS | `epic-games.js:11,74,154` | Page navigation, game claiming | Session cookies (via browser) |
| 2 | `www.epicgames.com/id/login` | HTTPS | `epic-games.js:12,86` | Email, password, OTP code | Yes: credentials typed into form |
| 3 | `gaming.amazon.com` | HTTPS | `prime-gaming.js:10,85,159,177` | Page navigation, game claiming | Session cookies (via browser) |
| 4 | `www.amazon.com/ap/signin` | HTTPS | `prime-gaming.js` (redirect) | Email, password, OTP code | Yes: credentials typed into form |
| 5 | `www.gog.com` | HTTPS | `gog.js:8,43,114,140` | Page navigation, game claiming, newsletter settings | Session cookies (via browser) |
| 6 | `www.gog.com` login iframe | HTTPS | `gog.js:52-64` | Email, password, OTP code | Yes: credentials typed into form |
| 7 | `www.unrealengine.com` | HTTPS | `unrealengine.js:13,48` | Page navigation, asset claiming | Session cookies (via browser) |
| 8 | `graphql.unrealengine.com/ue/graphql` | HTTPS | `unrealengine.js:50` | GraphQL queries (read) | Session cookies |
| 9 | `redeem.gog.com/v1/bonusCodes/*` | HTTPS | `prime-gaming.js:236,258` | Redemption code verification | GOG session cookies |
| 10 | `cart.production.store-web.dynamics.com` | HTTPS | `prime-gaming.js:286,298` | Xbox/Microsoft code redemption | Microsoft session cookies |
| 11 | `account.microsoft.com/billing/redeem` | HTTPS | `prime-gaming.js:212-213` | Code redemption page | Microsoft session cookies |
| 12 | `www.legacygames.com/primedeal` | HTTPS | `prime-gaming.js:214,316-320` | Coupon code + email address | `cfg.lg_email` |
| 13 | `promo.legacygames.com` | HTTPS | `prime-gaming.js:322` | Order processing | Form data |
| 14 | `login.aliexpress.com` | HTTPS | `aliexpress.js:42-43` | Email, password | Yes: credentials typed into form |
| 15 | `www.aliexpress.com`, `m.aliexpress.com` | HTTPS | `aliexpress.js:74-80` | Page navigation | Session cookies |
| 16 | `steamcommunity.com` | HTTPS | `steam-games.js:40` | Read-only game list page | No credentials (public profile) |
| 17 | `api.github.com` | HTTPS | `src/version.js:37` | GET request for latest commit | No credentials |
| 18 | **Apprise (via CLI)** | Varies | `src/util.js:122` | Game titles, claim status, URLs, redemption codes | No login creds; but codes and game URLs are sent |
| 19 | `deb.nodesource.com` | HTTPS | `Dockerfile:15` | Package download during build | No |
| 20 | `pypi.org` (pip) | HTTPS | `Dockerfile:52` | Package download during build | No |

**No unexpected/suspicious endpoints found. No telemetry. No analytics. No beaconing.**

---

## E) Hardening Checklist

Before running this with real (or even throwaway) credentials:

### Must Do (High Priority)

- [ ] **Set VNC_PASSWORD** — Never run Docker without setting this variable. Default is no password. (`docker run -e VNC_PASSWORD=<random>`)
- [ ] **Bind ports to localhost** — Change `docker-compose.yml` port binding to `127.0.0.1:6080:6080` to prevent network exposure.
- [ ] **Use throwaway accounts** — Create dedicated accounts for each store (Epic, Amazon, GOG) with unique passwords. Do NOT use your primary account.
- [ ] **Avoid DEBUG=1 in production** — Debug mode writes cookies to disk and logs network traffic including session URLs.

### Should Do (Medium Priority)

- [ ] **Review NOTIFY URL security** — If using Telegram/Discord/etc., ensure webhook URLs are kept secret. Redemption codes ARE sent in notifications (F10).
- [ ] **Restrict data volume permissions** — `chmod 700 data/` and ensure only your user can access the Docker volume.
- [ ] **Run container as non-root** — Add to docker-compose.yml: `user: "1000:1000"` (may require adjusting Dockerfile).
- [ ] **Pin dependency versions** — Replace `^` with exact versions in `package.json`, or verify `package-lock.json` integrity.
- [ ] **Run `npm audit`** — Check for known vulnerabilities in dependencies before running.
- [ ] **Restrict Docker container capabilities** — Add `--cap-drop=ALL --cap-add=SYS_ADMIN` (SYS_ADMIN needed for browser sandbox).

### Nice to Have (Low Priority)

- [ ] **Separate browser profiles per service** — Set different `BROWSER_DIR` for each script run to isolate sessions.
- [ ] **Clean up HAR/video recordings** — If `RECORD=1` is used, recordings contain full HTTP traffic. Delete after use.
- [ ] **Pin CI/CD action versions** — Change `sonarsource/sonarcloud-github-action@master` to a pinned SHA in your fork's workflows.
- [ ] **Network isolation** — Run container with `--network=none` for initial testing, then allowlist only required domains.

---

## F) Safe-Run Recommendation

### Is this repo safe to test?

**Yes, with a throwaway account and the precautions below.** The code does what it claims: it automates browser interactions to claim free games. There is no evidence of:
- Credential exfiltration to unauthorized third parties
- Hidden telemetry or analytics
- Backdoors or obfuscated code
- Malicious post-install scripts

### Recommended Isolation Measures

1. **Throwaway credentials** — Create a fresh Epic Games / Amazon / GOG account with a unique email and password. Do NOT reuse passwords from other services.
2. **Run in Docker** — The Dockerfile provides a reasonable isolation boundary.
3. **Set VNC_PASSWORD** — `docker run -e VNC_PASSWORD=$(openssl rand -hex 12) ...`
4. **Bind to localhost** — `-p 127.0.0.1:6080:6080` instead of `-p 6080:6080`
5. **Do NOT set DEBUG=1** — Avoid cookie dumps and verbose network logging.
6. **Monitor network** — Optionally run with `--network` isolation or use a firewall to only allow HTTPS to:
   - `*.epicgames.com`
   - `*.amazon.com`
   - `gaming.amazon.com`
   - `*.gog.com`
   - `*.unrealengine.com`
   - `api.github.com` (for version check only)
7. **Inspect data/ after run** — Check what was written to the volume (JSON databases, screenshots, recordings).
8. **Destroy container after testing** — `docker rm -v fgc` to remove the volume with all cached data.

### Extra Focus: EG_OTPKEY Confirmation

Based on full code trace:

| Question | Answer | Evidence |
|----------|--------|----------|
| 1. Is the TOTP seed kept local? | **YES** | `cfg.eg_otpkey` is read from env, passed only to `authenticator.generate()` (otplib), never stored or transmitted. See `epic-games.js:126`, `unrealengine.js:76`. |
| 2. Is the generated OTP kept local? | **YES** — it is only typed into the target login form | The OTP is stored in a local `const otp` variable, then passed to `page.locator(...).pressSequentially(otp.toString())` which types it into the Epic/Amazon MFA input field. |
| 3. Is the OTP or seed logged? | **NO** | Searched all `console.log/debug/error/info` calls. Neither `eg_otpkey`, `pg_otpkey`, nor the generated OTP values appear in any log statement. The only related log is `console.log('Enter the security code...')` which is a user instruction, not a value. |
| 4. Is either sent to any service other than the login provider? | **NO** | The OTP is only sent via Playwright `pressSequentially()` into an HTML input element on the legitimate login page (`**/id/login/mfa**` for Epic, `**/ap/mfa**` for Amazon). It is never included in notifications, never stored in the JSON database, never written to files. |

---

## Appendix: Dependency List

| Package | Version | Purpose | Risk Notes |
|---------|---------|---------|------------|
| `chalk` | ^5.4.1 | Terminal colors | Low risk, well-maintained |
| `cross-env` | ^7.0.3 | Cross-platform env vars | Low risk |
| `dotenv` | ^16.5.0 | Load .env files | Low risk, well-maintained |
| `enquirer` | ^2.4.1 | Interactive CLI prompts | Low risk |
| `fingerprint-injector` | ^2.1.66 | Browser fingerprint spoofing | Medium risk: Apify package, injects JS into browser context |
| `lowdb` | ^7.0.1 | JSON file database | Low risk |
| `otplib` | ^12.0.1 | TOTP generation | Low risk, well-maintained, security-relevant |
| `playwright-firefox` | ^1.52.0 | Browser automation | Medium risk: large attack surface (browser binary), but from Microsoft |
| `puppeteer-extra-plugin-stealth` | ^2.11.2 | Anti-detection evasion scripts | Medium risk: injects JS into every page, but well-known project |
| `eslint` | ^9.26.0 (dev) | Linter | Low risk, dev only |
| `@stylistic/eslint-plugin-js` | ^4.2.0 (dev) | ESLint style rules | Low risk, dev only |
| `apprise` (pip, in Docker) | latest | Notification CLI | Medium risk: installed without version pin via `pip install apprise` |

---

*End of Security Audit Report*
