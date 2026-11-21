# SecureMark: status and handoff

## State
The project is JavaScript/JSX with a Next.js 14 app, PostgreSQL JSONB state storage, Docker Compose deployment, and a 32-test Node.js suite.

## First steps for the next agent
1. Set `DATABASE_URL`, `SECUREMARK_SECRET`, and `SIGNING_KEY_PEM` in `.env`, then run `docker compose up --build` to start the app connected to Neon.
2. Click through: register (first user = admin) → protect image (DWT and DCT) → download PNG → check it (VERIFIED) → check a JPEG re-save (MODIFIED, "re-encoded") → paste over a region (heatmap) → certificate PDF scans to `/verify/SMK-…` → forgot/reset password → admin page.
3. Run `npm run eval` once to refresh `research/results.json` with your own photos (`SAMPLE_DIR=...`).

## Done in this round (vs previous handoff)
Fixed: lost-update race in persistent storage, key derivation (HKDF, lazy), image-width-dependent bit layout (now crop-searchable), exact-pixel tamper check (now tolerant 32px block fingerprints), duplicate-claim hole (watermarked/cropped/rotated copies can't be re-registered), self-check of every issued watermark.
Added: DCT embedding, SSIM, Reed-Solomon ECC, brightness compensation, crop/rotate/mirror/resize recovery, evidence z-score + "watermark-like but undecodable" state, pHash, EXIF, PDF certificate + QR, `/verify/[regId]`, admin dashboard, hash-chained audit log, email verification + password reset/change (session revocation via token version), rate limits, history page, research page + `npm run eval`, tests, Dockerfile/compose.

Cross-device deployments must share `SECUREMARK_SECRET`, `SIGNING_KEY_PEM`, Neon state, and the `securemark_image_files` table. Legacy per-device files can be imported with `npm run migrate:files`; signature status can be audited/resigned with the scripts documented in README.

## Latest fix: cropped images were registered as new
Crops of the unprotected original, and crops that were resized/re-encoded (watermark lost), passed the registration gate because it relied on watermark recovery only. `lib/match.js` now does crop/scale-aware pixel matching against all registered images; used in `registerImage` (409) and `verifyImage` (INCONCLUSIVE + `contentMatch`). Tests in `test/flow.test.js`. Known gaps: rotated/mirrored crops; linear cost in registered-image count (move coarse maps to a persisted/indexed store if the catalogue grows beyond a few hundred images).

## Known limits / ideas (priority order)
1. Contrast scaling and arbitrary-angle rotation break the lattice. Ideas: embed a known pilot pattern for scale/rotation estimation; or normalise contrast using block statistics before decoding.
2. DCT is fragile to blur and JPEG < q70 (see `research/results.md`); DWT is the default for that reason.
3. Move rate limits to a shared store; consider S3-compatible storage for images.
4. Dispute workflow, retention policy for stored files, BMP input (convert before sharp), AI forgery module (kept out on purpose; must stay independent of cryptographic verification).
5. Block-level tamper detection is not cryptographic: a fingerprint tolerance means small edits (< ~14 grey levels per 8×8 sub-region) are not flagged.

## Prompt for the next agent
Continue SecureMark (Next.js 14 project in this folder). Read README.md, this file, `lib/wm.js`, `lib/recover.js` and `lib/verify.js` first. Step 1: install dependencies, run `npm test`, `npm run build`, `npm run dev`, and fix everything that breaks, testing register/verify end-to-end with a real photo. Then work the "Known limits" list in order, adding a test and updating `research/results.*` for each robustness change. Keep the codebase minimal, keep every UI element functional, and never let a failed cryptographic check be reported as a valid watermark. If you run low on budget, stop, update this file and write a new continuation prompt.
