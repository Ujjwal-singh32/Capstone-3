import { audit, load, mutate } from "./db.js";
import { cellsOf, decodeImage, embedBits, encodePng, MIN_CELLS, sharpIn, ssim } from "./wm.js";
import { keyFingerprint, payloadBits, sign } from "./crypto.js";
import { PATTERN_Z, recover } from "./recover.js";
import { findContentMatch } from "./match.js";
import { fingerprint, metaOf, phash } from "./forensics.js";
import { HttpError, hamming, regIdOf, rid, sha256 } from "./util.js";
export const MAX_BYTES = 15 * 1024 * 1024;
const FORMATS = ["jpeg", "png", "webp", "tiff"]; // note: sharp/libvips cannot read BMP
/** Validate an upload, embed the encrypted watermark, store the protected PNG and the signed record. */
export async function registerImage(user, buf, rawName, alg) {
    if (buf.length > MAX_BYTES)
        throw new HttpError("File too large (15 MB maximum).", 413);
    let meta;
    try {
        meta = await sharpIn(buf).metadata();
    }
    catch {
        throw new HttpError("That file is not a readable image.");
    }
    if (!FORMATS.includes(meta.format || ""))
        throw new HttpError("Unsupported format. Use JPEG, PNG, WebP or TIFF.");
    if ((meta.pages || 1) > 1)
        throw new HttpError("Animated or multi-page images are not supported.");
    let up;
    try {
        up = await decodeImage(buf);
    }
    catch {
        throw new HttpError("The image could not be decoded (it may be corrupt or too large; 24 megapixels maximum).");
    }
    if (cellsOf(up.w, up.h) < MIN_CELLS)
        throw new HttpError(`Image too small: about 240 x 240 pixels are needed to carry the watermark (yours is ${up.w} x ${up.h}).`);
    const orig = sha256(buf), db = await load();
    const dup = db.images.find(i => i.record.orig === orig || i.record.wm === orig);
    if (dup)
        throw new HttpError(`This exact file is already registered as ${dup.record.regId}.`, 409);
    // someone must not be able to claim an already-protected image (or a resized/rotated/cropped copy of one) as their own
    const prior = await recover(buf, db);
    if (prior.found) {
        const o = db.images.find(i => i.n === prior.found.reg);
        throw new HttpError(`This image already carries a SecureMark watermark${o ? ` (${o.record.regId})` : ""} and cannot be registered again.`, 409);
    }
    if (prior.patternZ >= PATTERN_Z)
        throw new HttpError("This image contains a SecureMark-like watermark that could not be verified and cannot be registered again.", 409);
    // the watermark may be gone (crop of the unprotected original, or a crop that was resized/re-encoded): compare the pixels themselves
    const copy = await findContentMatch(up, db);
    if (copy)
        throw new HttpError(`This image is ${copy.retainedPct < 97 ? `a cropped part (about ${copy.retainedPct}% of the area)` : "a resized or re-encoded copy"} of ${copy.regId} (${Math.round(copy.ncc * 100)}% pixel similarity), which is already registered, so it cannot be registered again.`, 409);
    const n = await mutate(d => ++d.seq.img), ts = Math.floor(Date.now() / 1000), at = new Date(ts * 1000);
    const { img: wm, psnr } = embedBits(up, payloadBits(n, user.n, ts), alg);
    const png = await encodePng(wm);
    const self = await recover(png); // never hand out a copy whose watermark cannot be read back
    if (!self.found || self.found.reg !== n)
        throw new HttpError("This image cannot carry a reliable watermark (large pure-black or pure-white areas clip the embedding). Try a different image.", 422);
    const ph = await phash(wm), metaO = await metaOf(buf);
    const similar = db.images.map(i => ({ regId: i.record.regId, distance: hamming(ph, i.record.ph) })).filter(s => s.distance <= 10).sort((a, b) => a.distance - b.distance).slice(0, 5);
    const record = { v: 1, regId: regIdOf(n, at), owner: user.n, at: at.toISOString(), alg, orig, wm: sha256(png), w: wm.w, h: wm.h, ph, keyFingerprint: keyFingerprint() };
    const id = rid(8), ss = +ssim(up, wm).toFixed(4);
    const fp = fingerprint(wm);
    await mutate(d => {
        d.images.push({ id, n, userId: user.id, name: rawName.replace(/[^\w.\- ]+/g, "_").slice(0, 120) || "image", record, sig: sign(record), psnr: +psnr.toFixed(2), ssim: ss, exif: metaO, bytes: png.length });
        audit(d, "register", user.id, { regId: record.regId, alg });
    }, { id, png, fp });
    return { id, regId: record.regId, psnr: +psnr.toFixed(2), ssim: ss, alg, w: wm.w, h: wm.h, similar };
}
