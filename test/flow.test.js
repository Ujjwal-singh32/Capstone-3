import test from "node:test";
import assert from "node:assert/strict";
import "./env.js";
import { makePhoto } from "./helpers.js";
import { mutate, load, auditChainOk } from "../lib/db.js";
import { registerImage } from "../lib/register.js";
import { verifyImage } from "../lib/verify.js";
import { sha256 } from "../lib/util.js";
import * as A from "../scripts/attacks.js";
import { execFileSync } from "node:child_process";
import fs from "fs";
import path from "path";
import { FILES } from "../lib/db.js";
const who = { userId: null, ip: "1.2.3.4" };
let alice, bob, orig, protectedPng, regId = "";
test("setup: two users and one registered image", async () => {
    await mutate(d => {
        for (const [i, name] of ["Alice", "Bob"].entries())
            d.users.push({ id: "u" + i, n: ++d.seq.user, name, email: name + "@x.io", hash: "x", role: "USER", active: true, verified: true, tv: 0, at: new Date().toISOString() });
    });
    [alice, bob] = (await load()).users;
    orig = await makePhoto(512, 384, 21);
    const r = await registerImage(alice, orig, "holiday photo.png", "dwt");
    regId = r.regId;
    assert.match(r.regId, /^SMK-\d{4}-000001$/);
    assert.ok(r.psnr > 30 && r.ssim > 0.9);
    assert.match((await load()).images[0].record.keyFingerprint, /^[0-9a-f]{16}$/);
    protectedPng = fs.readFileSync(path.join(FILES, r.id + ".png"));
});
test("registered copy verifies as VERIFIED with owner and valid signature", async () => {
    const v = await verifyImage(protectedPng, who);
    assert.equal(v.status, "VERIFIED");
    assert.equal(v.owner, "Alice");
    assert.equal(v.regId, regId);
    assert.equal(v.recordSignatureValid, true);
    assert.equal(v.cryptoValid, true);
});
test("JPEG re-save: MODIFIED but classified as re-encoded, zero changed blocks (the old exact-pixel check flagged everything)", async () => {
    for (const q of [92, 75, 60]) {
        const v = await verifyImage(await A.jpeg(q)(protectedPng), who);
        assert.equal(v.status, "MODIFIED", `q${q}`);
        assert.equal(v.kind, "reencoded", `q${q} ${JSON.stringify(v.tamper && { pct: v.tamper.pct })}`);
        assert.equal(v.tamper.bad.length, 0);
    }
});
test("pasted patch: localised to the right blocks only", async () => {
    const v = await verifyImage(await A.paste(256, 192, 96, 0.05, 0.05)(protectedPng), who);
    assert.equal(v.status, "MODIFIED");
    assert.equal(v.kind, "local");
    const t = v.tamper, cols = new Set(t.bad.map(i => i % t.gw)), rows = new Set(t.bad.map(i => Math.floor(i / t.gw)));
    assert.ok(t.bad.length >= 4 && t.pct < 15, `pct ${t.pct}`);
    assert.ok([...cols].every(c => c >= 7 && c <= 11) && [...rows].every(r => r >= 5 && r <= 9), "changed blocks must lie around the pasted area");
    assert.ok(v.heatmap?.startsWith("data:image/jpeg;base64,"));
});
test("brightness edits are survived and classified as a global change", async () => {
    const v = await verifyImage(await A.brightness(30)(protectedPng), who);
    assert.equal(v.status, "MODIFIED");
    assert.equal(v.kind, "global");
    assert.ok(v.tamper && v.tamper.pct > 80, `pct ${v.tamper?.pct}`);
});
test("strong contrast scaling destroys the watermark (documented limit): reported honestly as not found, never as verified", async () => {
    const v = await verifyImage(await A.contrastBy(1.4)(protectedPng), who);
    assert.notEqual(v.status, "VERIFIED");
    assert.equal(v.cryptoValid, false);
    assert.match(v.reason || "", /does not prove/);
});
test("cropped copy: MODIFIED, reported as cropped with retained percentage, no bogus heatmap", async () => {
    const v = await verifyImage(await A.cropFrac(0.5, 0.4, 0.3)(protectedPng), who);
    assert.equal(v.status, "MODIFIED");
    assert.equal(v.kind, "cropped");
    assert.ok(Math.abs(v.retainedPct - 50) < 3);
    assert.equal(v.heatmap, undefined);
});
test("rotated by 90 degrees: recovered, compared in registered orientation, flagged as re-encoded geometry only", async () => {
    const v = await verifyImage(await A.rotate(90)(protectedPng), who);
    assert.equal(v.status, "MODIFIED");
    assert.match(v.align || "", /rotated (90|270)/);
    assert.equal(v.tamper?.bad.length, 0);
});
test("missing block fingerprint keeps verification modified but omits tamper heatmap", async () => {
    const image = (await load()).images[0], fpFile = path.join(FILES, image.id + ".fp"), fp = fs.readFileSync(fpFile);
    fs.unlinkSync(fpFile);
    try {
        const v = await verifyImage(await A.brightness(15)(protectedPng), who);
        assert.equal(v.status, "MODIFIED");
        assert.equal(v.tamper, undefined);
        assert.equal(v.heatmap, undefined);
    }
    finally {
        fs.writeFileSync(fpFile, fp);
    }
});
test("the original, unprotected upload is never VERIFIED; its pixels are matched to the registered image as a POTENTIAL_MATCH", async () => {
    const v = await verifyImage(orig, who);
    assert.equal(v.status, "POTENTIAL_MATCH");
    assert.equal(v.cryptoValid, false);
    assert.equal(v.contentMatch?.regId, regId);
});
test("an unrelated image still verifies as UNREGISTERED (no false content match)", async () => {
    const v = await verifyImage(await makePhoto(512, 384, 777), who);
    assert.equal(v.status, "UNREGISTERED");
    assert.equal(v.contentMatch, undefined);
});
test("crops WITHOUT a surviving watermark are caught by content matching: crop of the unprotected original, resized crop, edited crop", async () => {
    const big = await makePhoto(1024, 768, 55), r = await registerImage(alice, big, "big.png", "dwt");
    const sharp = (await import("sharp")).default, crop = (b, l, t, w, h) => sharp(b).extract({ left: l, top: t, width: w, height: h }).png().toBuffer();
    const protectedBig = fs.readFileSync(path.join(FILES, r.id + ".png"));
    const cases = {
        "crop of the unprotected original": await crop(big, 100, 80, 614, 460),
        "small crop of the original": await crop(big, 300, 200, 400, 300),
        "crop of the original, JPEG q80": await A.jpeg(80)(await crop(big, 100, 80, 614, 460)),
        "crop of the protected copy, then resized to 50%": await A.resize(0.5)(await crop(protectedBig, 100, 80, 614, 460)),
        "crop of the original, resized by 0.62": await A.resize(0.62)(await crop(big, 150, 100, 700, 500)),
        "crop of the original with brightness change": await A.brightness(20)(await crop(big, 100, 100, 500, 380)),
    };
    for (const [name, img] of Object.entries(cases)) {
        await assert.rejects(registerImage(bob, img, "crop.png", "dwt"), (e) => e.status === 409 && e.message.includes(r.regId), name);
        const v = await verifyImage(img, who);
        assert.notEqual(v.status, "VERIFIED", name);
        assert.equal(v.status, "POTENTIAL_MATCH", name);
        assert.equal(v.contentMatch?.regId, r.regId, name);
        assert.ok(v.contentMatch.confidence >= 88 && v.contentMatch.confidence <= 100, name);
        assert.ok(v.contentMatch.originalPreview.startsWith("data:image/jpeg") && v.contentMatch.uploadPreview.startsWith("data:image/jpeg"), name);
    }
    const c = (await verifyImage(cases["small crop of the original"], who)).contentMatch;
    assert.ok(c.retainedPct < 20 && Math.abs(c.region.left - 300) <= 8 && Math.abs(c.region.top - 200) <= 8, JSON.stringify(c.region));
    const stored = (await load()).verifications.filter(x => x.status === "POTENTIAL_MATCH").at(-1);
    assert.equal(stored.result.contentMatch.originalPreview, undefined); // previews are not persisted
    // a genuinely different photo of the same size is NOT blocked
    await registerImage(bob, await makePhoto(1024, 768, 56), "different.png", "dwt");
});

test("duplicates are rejected: same file, and an already-watermarked copy submitted by someone else", async () => {
    await assert.rejects(registerImage(alice, orig, "again.png", "dwt"), /already registered/);
    await assert.rejects(registerImage(bob, protectedPng, "stolen.png", "dwt"), /already registered/);
    await assert.rejects(registerImage(bob, await A.jpeg(80)(protectedPng), "recompressed.jpg", "dwt"), /already carries a SecureMark watermark/);
    await assert.rejects(registerImage(bob, await A.cropFrac(0.6, 0.3, 0.3)(protectedPng), "cropped.png", "dwt"), /already carries/);
    const mismatchImage = path.join(FILES, "wrong-key-recompressed.jpg");
    fs.writeFileSync(mismatchImage, await A.jpeg(80)(protectedPng));
    try {
        const script = `import fs from "node:fs"; import { registerImage } from "./lib/register.js"; try { await registerImage({ id: "u1", n: 2 }, fs.readFileSync(process.argv[1]), "wrong-key.jpg", "dwt"); process.exitCode = 1; } catch (e) { if (e.status !== 409 || !e.message.includes("SecureMark-like watermark")) { console.error(e); process.exitCode = 2; } }`;
        assert.doesNotThrow(() => execFileSync(process.execPath, ["--input-type=module", "-e", script, mismatchImage], {
            cwd: process.cwd(),
            env: { ...process.env, SECUREMARK_SECRET: "different-key-for-test" },
        }));
    }
    finally {
        fs.unlinkSync(mismatchImage);
    }
});
test("validation: garbage, tiny and unsupported inputs get clear errors", async () => {
    await assert.rejects(registerImage(bob, Buffer.from("not an image at all"), "x.png", "dwt"), /not a readable image/);
    await assert.rejects(registerImage(bob, await makePhoto(100, 100, 2), "tiny.png", "dwt"), /too small/);
    await assert.rejects(verifyImage(Buffer.from("junk"), who), /not a readable image/);
});
test("DCT registration works and is identified as DCT", async () => {
    const img = await makePhoto(448, 352, 33), r = await registerImage(bob, img, "dct.png", "dct");
    const v = await verifyImage(fs.readFileSync(path.join(FILES, r.id + ".png")), who);
    assert.equal(v.status, "VERIFIED");
    assert.equal(v.alg, "dct");
    assert.equal(v.owner, "Bob");
});
test("tampering with a stored record is detected through the Ed25519 signature", async () => {
    await mutate(d => { d.images[0].record.at = "2001-01-01T00:00:00.000Z"; });
    const v = await verifyImage(protectedPng, who);
    assert.equal(v.status, "INCONCLUSIVE");
    assert.equal(v.recordSignatureValid, false);
});
test("audit log is hash-chained and detects edits", async () => {
    const db = await load();
    assert.ok(db.audit.length > 5);
    assert.equal(auditChainOk(db), true);
    await mutate(d => { d.audit[2].details = { forged: true }; });
    assert.equal(auditChainOk(await load()), false);
    void sha256;
});
