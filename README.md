# Mind Coach

Mind Coach is a personal well-being reflection site. Its questionnaires are educational exercises, not clinically validated assessments or diagnoses.

The optional deeper reflection contains 24 questions about emotional awareness, recovering after stress, social support, personal boundaries, daily rhythm, and values. It summarizes four frequency responses per area as a descriptive 0–9 average and offers a few prompts. It is a custom, unvalidated exercise: scores are not clinical measures, personality traits, or a diagnosis. Guest summaries stay in the browser; signed-in users can opt in to saving summary scores to their local account database. Individual answers are not sent to the account server.

## Run locally

Requires Node.js 24.7 or newer.

```sh
npm start
```

Open `http://127.0.0.1:3000`. Account features require the site to run through this server; opening `index.htm` directly supports local guest results only.

## Tests

```sh
npm test
```

## Accounts and privacy

Creating an account is optional. Account creation requires consent to save test scores; weekly reports have a separate opt-in. Questionnaire answers are not sent to the server. The local SQLite database is stored in `.data/mind-coach.sqlite` and is excluded from version control.

This is a local starter, not a production-ready service. Do not expose it to the public internet as-is. A real deployment needs HTTPS, a reviewed hosting and database setup, backups, a decision about encryption at rest, account verification and recovery, persistent abuse controls, and a security review.

## Security notes

New passwords are stored as Argon2id hashes with per-account random salts; they are not encrypted in a reversible form. Existing scrypt accounts are upgraded after their next successful sign-in. New passwords must be 15–128 characters; a long, unique passphrase is recommended. Sign-in and registration requests are rate-limited, state-changing API calls require a same-origin request, and session cookies are `HttpOnly` and `SameSite=Strict` (and `Secure` in production).

Saved assessment scores and generated weekly summaries are encrypted in the database with AES-256-GCM. Existing plaintext score and report rows are encrypted in a transaction the next time the server starts. Account emails, result dates, assessment mode, and account metadata remain readable in SQLite; individual questionnaire answers are not sent to or stored by the account server.

For local development, the server creates a random 32-byte key beside the local database at `.data/mind-coach.sqlite.key`. Keep that file: losing it makes encrypted scores unreadable. The local key is kept in the ignored `.data` folder for convenience, so protect the folder and backups together. For production, set `DATA_ENCRYPTION_KEY` as a secret in the hosting provider before starting the server. It must be exactly 64 hexadecimal characters (32 random bytes); generate it with `node --input-type=module -e "import { randomBytes } from 'node:crypto'; console.log(randomBytes(32).toString('hex'))"`. Never commit the key or put it in browser code. Keep the same key across deployments and backups, and store a protected backup separately. If the key is lost or changed without re-encrypting the data, the encrypted results cannot be recovered.

For a production reverse-proxy deployment, set `NODE_ENV=production` and `PUBLIC_ORIGIN=https://your-domain.example`. Set `TRUST_PROXY=1` only when a trusted TLS reverse proxy controls the forwarded protocol header. Production mode refuses to start without an HTTPS `PUBLIC_ORIGIN`.

The current Tailwind Play CDN is intended for development; its runtime requires inline-style and script-evaluation allowances. Before public deployment, build Tailwind into a local static CSS file and remove the CDN and those runtime allowances. Application-level encryption protects saved score and report contents if a database copy is exposed without the key; it does not encrypt the entire SQLite file or protect data from a compromised running server. Use the hosting provider's secret manager for the production key and enable encrypted storage and backups. This starter does not yet provide MFA, email verification, password recovery, or distributed rate limiting. No application can promise protection from every attack; review the complete hosting, TLS, database, and recovery setup before storing real personal data.
