# The Huddle

A private, single-file internal alignment site. Everything meaningful in
`index.html` is AES-256-GCM encrypted; visitors see only a sign-in screen, and
each signed-in reader gets a personalized view. There is no backend — the site
works on GitHub Pages or opened directly as a local file.

## How it works

- `index.html` is a **built artifact**: a login shell plus encrypted payloads.
  Keys are derived from each reader's credentials (PBKDF2-SHA256 → AES-GCM), so
  a successful decryption *is* the credential check. Usernames and passwords
  are not case-sensitive.
- Each reader's payload contains their personalized section; admin users see
  every personalized section. Reader responses save to their own browser
  (localStorage) and are emailed to the site owner from the Feedback page —
  nothing is transmitted otherwise.
- The plaintext sources (`content/`, `users.json`) are **gitignored and never
  committed** — this repo is public, and only ciphertext lands in it.

## Editing content

From a clone that has `content/` and `users.json`:

```
# edit content/site-src.html or content/panels/<user>.html, then:
node tools/build.mjs
```

From a **fresh clone** (no plaintext present):

```
node tools/export.mjs <admin-username> <admin-password>   # recovers content/
cp users.example.json users.json                          # then fill in real users
node tools/build.mjs
```

## Adding a reader

1. Add a row to `users.json` (see `users.example.json` for the schema; set
   `"admin": true` only for users who should see every panel).
2. Create `content/panels/<username>.html` with their personalized section.
3. `node tools/build.mjs`, commit `index.html`, push.

## Deployment (GitHub Pages)

Pages serves this repo from the `main` branch root; `.nojekyll` disables the
Jekyll build step. Two operational notes:

- **Changing the Pages source setting cancels in-flight deployments** — that
  looks like "failed" runs in the Actions tab. Don't toggle settings to fix a
  slow deploy; instead re-run the failed "pages build and deployment" run from
  the Actions tab, or push any new commit.
- A successful deploy typically goes live within a minute or two.

## Security posture (read this)

This protects against casual access, search engines, and repository browsing —
**it is not high-grade secrecy**. Anyone who obtains (or guesses) a reader's
credentials can decrypt what that reader can see. Use passwords accordingly,
rotate them by editing `users.json` and rebuilding, and keep anything truly
sensitive out of the site entirely.
