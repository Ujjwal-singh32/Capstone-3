import { audit, getImageFile, load, mutate } from "./db.js";
import { keyFingerprint, sigOk } from "./crypto.js";
import { recover, PATTERN_Z } from "./recover.js";
import { findContentMatch } from "./match.js";
import { changedBlocks, fingerprint, gridOf, BLK, heatmap, matchPreviews, metaChanges, metaOf, phash } from "./forensics.js";
import { MAX_BYTES } from "./register.js";
import { HttpError, hamming, rid, sha256 } from "./util.js";
const describe = (a) => a.kind === "orient" ? `rotated ${a.rot}°${a.flop ? " and mirrored" : ""} (undone for comparison)`
    : a.kind === "resized" ? `resized from ${a.from[0]}x${a.from[1]} to ${a.to[0]}x${a.to[1]} for comparison`
        : a.kind === "crop" ? "cropped" : undefined;
/** Public view of one registration (never exposes e-mail, storage paths or the user's id). */
export async function publicRecord(regId) {
    const db = await load(), img = db.images.find(i => i.record.regId === regId);
    if (!img)
        return null;
    return { regId, owner: db.users.find(u => u.n === img.record.owner)?.name ?? "unknown", registeredAt: img.record.at, alg: img.record.alg, width: img.record.w, height: img.record.h, registeredHash: img.record.wm, recordSignatureValid: sigOk(img.record, img.sig), keyFingerprint: img.record.keyFingerprint ?? null, serverKeyFingerprint: keyFingerprint() };
}
/**
 * Full verification pipeline: recover watermark -> authenticate (AES-GCM) -> look up the registration -> check its Ed25519
 * signature -> compare SHA-256 -> if different, localise changes with block fingerprints.
 */
export async function verifyImage(buf, who) {
    if (buf.length > MAX_BYTES)
        throw new HttpError("File too large (15 MB maximum).", 413);
    const db = await load(), hash = sha256(buf);
    let rec;
    try {
        rec = await recover(buf, db);
    }
    catch {
        throw new HttpError("That file is not a readable image (or it is larger than 24 megapixels).");
    }
    const { found, up, patternZ } = rec;
    const res = { id: "VRF-" + rid(6).toUpperCase(), at: new Date().toISOString(), status: "UNREGISTERED", cryptoValid: !!found, hash, serverKeyFingerprint: keyFingerprint() };
    const upMeta = await metaOf(buf).catch(() => ({}));
    res.meta = { uploaded: upMeta, changes: [] };
    const img = found ? db.images.find(i => i.n === found.reg) : undefined;
    if (!found) {
        res.patternDetected = patternZ >= PATTERN_Z;
        if (res.patternDetected) {
            res.status = "INCONCLUSIVE";
            res.reason = "A watermark-like pattern is present but could not be decoded; the image is probably heavily edited, resized or compressed.";
        }
        else
            res.reason = "No SecureMark watermark could be recovered. This does not prove the image is unregistered: heavy editing can destroy the watermark.";
        const ph = await phash(up);
        res.similar = db.images.map(i => ({ regId: i.record.regId, distance: hamming(ph, i.record.ph) })).filter(s => s.distance <= 10).sort((a, b) => a.distance - b.distance).slice(0, 5);
        // no decodable watermark (e.g. a crop of the unprotected original): still compare the pixels with every registered image
        const copy = await findContentMatch(up, db);
        if (copy) {
            const o = db.images.find(i => i.n === copy.n), png = o && await getImageFile(o.id, "png"), cropped = copy.retainedPct < 97;
            res.status = "POTENTIAL_MATCH";
            res.kind = cropped ? "cropped" : "resized";
            res.contentMatch = { regId: copy.regId, owner: db.users.find(u => u.n === o?.record.owner)?.name, similarity: copy.ncc, confidence: Math.round(copy.ncc * 100), retainedPct: copy.retainedPct,
                region: { left: copy.left, top: copy.top, width: copy.width, height: copy.height }, registeredSize: [copy.regW, copy.regH] };
            if (png)
                Object.assign(res.contentMatch, await matchPreviews(png, copy, up));
            res.reason += ` However, the pixels match ${cropped ? `a cropped part (about ${copy.retainedPct}% of the area)` : "a resized or re-encoded copy"} of the registered image ${copy.regId} with ${res.contentMatch.confidence}% pixel similarity. This is visual evidence only, not a cryptographic proof of ownership.`;
        }
    }
    else if (!img) {
        res.status = "INCONCLUSIVE";
        res.reason = "A valid SecureMark watermark was found, but this server has no matching registration record.";
    }
    else {
        const r = img.record, owner = db.users.find(u => u.n === r.owner);
        Object.assign(res, { regId: r.regId, owner: owner?.name, registeredAt: r.at, alg: r.alg, registeredHash: r.wm, keyFingerprint: r.keyFingerprint ?? null });
        res.recordSignatureValid = sigOk(r, img.sig);
        res.meta.registered = img.exif;
        res.meta.changes = metaChanges(img.exif, upMeta);
        if (!res.recordSignatureValid) {
            res.status = "INCONCLUSIVE";
            res.reason = r.keyFingerprint && r.keyFingerprint !== res.serverKeyFingerprint
                ? `This record was signed by a different key than this server uses (record: ${r.keyFingerprint}; this server: ${res.serverKeyFingerprint}).`
                : `The stored registration record failed its signature check and cannot be trusted (this server: ${res.serverKeyFingerprint}).`;
        }
        else if (found.owner !== r.owner || found.ts * 1000 !== Date.parse(r.at)) {
            res.status = "INCONCLUSIVE";
            res.reason = "The embedded payload does not match the registration record.";
        }
        else if (hash === r.wm)
            res.status = "VERIFIED";
        else {
            res.status = "MODIFIED";
            res.align = describe(found.align);
            const al = found.aligned;
            if (found.align.kind === "crop") {
                res.kind = "cropped";
                res.retainedPct = +(100 * (up.w * up.h) / (r.w * r.h)).toFixed(1);
            }
            else if (al && al.w === r.w && al.h === r.h) {
                const fp = await getImageFile(img.id, "fp");
                if (fp) {
                    const bad = changedBlocks(fp, fingerprint(al)), { gw, gh } = gridOf(r.w, r.h), pct = +((100 * bad.length) / (gw * gh)).toFixed(1);
                    const kind = bad.length === 0 ? "reencoded" : pct >= 80 ? "global" : "local";
                    res.tamper = { B: BLK, gw, gh, w: r.w, h: r.h, bad, pct, kind };
                    res.kind = kind;
                    if (bad.length)
                        res.heatmap = await heatmap(al, bad);
                }
            }
        }
    }
    await mutate(d => {
        const { heatmap: _h, meta, tamper, contentMatch, ...summary } = res;
        if (contentMatch) { const { originalPreview: _o, uploadPreview: _u, ...cm } = contentMatch; summary.contentMatch = cm; } // keep stored history small
        d.verifications.push({ id: res.id, at: res.at, status: res.status, kind: res.kind, regId: res.regId, hash, userId: who.userId, ip: sha256("ip:" + who.ip).slice(0, 16),
            result: { ...summary, pct: tamper?.pct, changes: meta?.changes } });
        if (d.verifications.length > 20000)
            d.verifications.splice(0, d.verifications.length - 20000);
        audit(d, "verify", who.userId, { id: res.id, status: res.status, regId: res.regId });
    });
    return res;
}
