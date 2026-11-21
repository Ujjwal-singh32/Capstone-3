import sharp from "sharp";
import { getImageFile } from "./db.js";
/**
 * Content-based "is this a crop of something already registered?" check.
 *
 * Watermark recovery (recover.js) only helps when the watermark survives. A crop of the ORIGINAL upload never carried one,
 * and a crop that was then resized / re-encoded may have lost it, so both used to be registered as brand-new images.
 * Here the upload is slid over every registered image (multi-scale template matching with zero-mean normalised
 * cross-correlation, which ignores brightness/contrast changes and tolerates JPEG noise and the watermark itself):
 *  1. coarse search: all plausible scales x all positions on a 64/128 px thumbnail of each registered image;
 *  2. refinement of the best few candidates on a 256 px version, with the scale fine-tuned.
 * A match needs NCC >= MATCH_NCC over the whole upload, so unrelated images do not collide.
 * Not covered: crops that are also rotated/mirrored (the watermark path handles those when it survives).
 */
export const MATCH_NCC = 0.88;
const COARSE_NCC = 0.7, MIN_STD = 4, L1 = 64, L2 = 128, LF = 256, BASE = 1280;
const SCALES = (() => { const a = []; for (let s = 0.25; s <= 3.01; s *= 1.08)
    a.push(s); return a; })();
const cache = new Map(); // image id -> coarse maps (registered images never change, so this is safe)
const CACHE_MAX = 400;
const toMap = (u8, w, h, rw, rh) => ({ w, h, d: Float32Array.from(u8), cx: w / rw, cy: h / rh, I1: null, I2: null });
async function grey(input, raw, w, h) {
    const s = raw ? sharp(input, { raw }) : sharp(input);
    const { data } = await s.resize(w, h, { fit: "fill", kernel: "lanczos3" }).greyscale().raw().toBuffer({ resolveWithObject: true });
    return data;
}
const dimsFor = (w, h, L) => { const k = Math.min(1, L / Math.max(w, h)); return [Math.max(8, Math.round(w * k)), Math.max(8, Math.round(h * k))]; };
async function levelMap(im, L) {
    const png = await getImageFile(im.id, "png");
    if (!png)
        return null;
    const { w, h } = im.record, [mw, mh] = dimsFor(w, h, L);
    return toMap(await grey(png, null, mw, mh), mw, mh, w, h);
}
async function coarseMaps(im) {
    const hit = cache.get(im.id);
    if (hit !== undefined)
        return hit;
    const m2 = await levelMap(im, L2);
    let out = null;
    if (m2) {
        const w1 = Math.max(8, m2.w >> 1), h1 = Math.max(8, m2.h >> 1), d = new Uint8Array(w1 * h1);
        for (let y = 0; y < h1; y++)
            for (let x = 0; x < w1; x++) {
                const x2 = Math.min(m2.w - 1, 2 * x), y2 = Math.min(m2.h - 1, 2 * y), x3 = Math.min(m2.w - 1, x2 + 1), y3 = Math.min(m2.h - 1, y2 + 1);
                d[y * w1 + x] = (m2.d[y2 * m2.w + x2] + m2.d[y2 * m2.w + x3] + m2.d[y3 * m2.w + x2] + m2.d[y3 * m2.w + x3]) / 4;
            }
        const { w, h } = im.record;
        out = { m1: toMap(d, w1, h1, w, h), m2 };
    }
    if (cache.size >= CACHE_MAX)
        cache.delete(cache.keys().next().value);
    cache.set(im.id, out);
    return out;
}
function integrals(m) {
    if (m.I1)
        return;
    const W = m.w + 1, I1 = new Float64Array(W * (m.h + 1)), I2 = new Float64Array(W * (m.h + 1));
    for (let y = 0; y < m.h; y++) {
        let r1 = 0, r2 = 0;
        for (let x = 0; x < m.w; x++) {
            const v = m.d[y * m.w + x];
            r1 += v;
            r2 += v * v;
            I1[(y + 1) * W + x + 1] = I1[y * W + x + 1] + r1;
            I2[(y + 1) * W + x + 1] = I2[y * W + x + 1] + r2;
        }
    }
    m.I1 = I1;
    m.I2 = I2;
}
/** Best zero-mean NCC of template T (tw x th) inside map m, for top-left positions in [xa,xb] x [ya,yb]. */
function search(m, T, tw, th, xa, xb, ya, yb) {
    if (tw > m.w || th > m.h)
        return null;
    integrals(m);
    const n = tw * th, tm = new Float32Array(n);
    let mean = 0;
    for (let i = 0; i < n; i++)
        mean += T[i];
    mean /= n;
    let tn = 0;
    for (let i = 0; i < n; i++) {
        tm[i] = T[i] - mean;
        tn += tm[i] * tm[i];
    }
    if (Math.sqrt(tn / n) < MIN_STD)
        return null; // flat template: correlation would be meaningless
    tn = Math.sqrt(tn);
    const W = m.w + 1, { I1, I2, d } = m, x0 = Math.max(0, xa), x1 = Math.min(m.w - tw, xb), y0 = Math.max(0, ya), y1 = Math.min(m.h - th, yb);
    let best = null;
    for (let y = y0; y <= y1; y++)
        for (let x = x0; x <= x1; x++) {
            const a = y * W + x, b = a + tw, c = (y + th) * W + x, e = c + tw;
            const sum = I1[e] - I1[b] - I1[c] + I1[a], sq = I2[e] - I2[b] - I2[c] + I2[a], v = sq - (sum * sum) / n;
            if (v < n * MIN_STD * MIN_STD)
                continue;
            let dot = 0;
            for (let j = 0; j < th; j++) {
                const ro = (y + j) * m.w + x, to = j * tw;
                for (let i = 0; i < tw; i++)
                    dot += tm[to + i] * d[ro + i];
            }
            const s = dot / (tn * Math.sqrt(v));
            if (!best || s > best.s)
                best = { s, x, y };
        }
    return best;
}
/**
 * Does `up` (a decoded upload) look like a crop / resized crop / re-encoded copy of any registered image?
 * Returns the best match { regId, n, ncc, retainedPct, scale } or null.
 */
export async function findContentMatch(up, db) {
    if (!db.images.length)
        return null;
    const [bw, bh] = dimsFor(up.w, up.h, BASE);
    const rawIn = { width: up.w, height: up.h, channels: 3 };
    const baseGrey = await grey(Buffer.from(up.rgb.buffer, up.rgb.byteOffset, up.rgb.length), rawIn, bw, bh);
    const tcache = new Map();
    const tpl = async (tw, th) => {
        const key = tw + "x" + th;
        let t = tcache.get(key);
        if (!t) {
            t = Float32Array.from(await grey(baseGrey, { width: bw, height: bh, channels: 1 }, tw, th));
            tcache.set(key, t);
        }
        return t;
    };
    const cands = [];
    for (const im of db.images) {
        const { w: rw, h: rh } = im.record;
        if (up.w > rw * 3 || up.h > rh * 3 || up.w < rw * 0.02)
            continue;
        const maps = await coarseMaps(im);
        if (!maps)
            continue;
        let best = null;
        for (const s of SCALES) {
            const tw0 = up.w / s, th0 = up.h / s;
            if (tw0 > rw * 1.03 || th0 > rh * 1.03)
                continue; // the crop cannot be larger than the registered image
            let m = maps.m1, tw = Math.round(up.w * m.cx / s), th = Math.round(up.h * m.cy / s);
            if (Math.max(tw, th) < 20) {
                m = maps.m2;
                tw = Math.round(up.w * m.cx / s);
                th = Math.round(up.h * m.cy / s);
            }
            tw = Math.min(tw, m.w);
            th = Math.min(th, m.h);
            if (Math.min(tw, th) < 8)
                continue;
            const r = search(m, await tpl(tw, th), tw, th, 0, m.w, 0, m.h);
            if (r && (!best || r.s > best.s))
                best = { ...r, scale: s, m, tw, th };
        }
        if (best && best.s >= COARSE_NCC)
            cands.push({ im, best });
    }
    cands.sort((a, b) => b.best.s - a.best.s);
    let hit = null;
    for (const { im, best } of cands.slice(0, 3)) {
        const { w: rw, h: rh } = im.record, [fw, fh] = dimsFor(rw, rh, LF), png = await getImageFile(im.id, "png");
        if (!png)
            continue;
        const f = toMap(await grey(png, null, fw, fh), fw, fh, rw, rh);
        const ccx = ((best.x + best.tw / 2) / best.m.cx) * f.cx, ccy = ((best.y + best.th / 2) / best.m.cy) * f.cy, pad = Math.ceil(f.cx / best.m.cx) + 2;
        for (const k of [0.92, 0.96, 1, 1.04, 1.08]) {
            const s = best.scale * k, tw = Math.min(f.w, Math.round(up.w * f.cx / s)), th = Math.min(f.h, Math.round(up.h * f.cy / s));
            if (Math.min(tw, th) < 8)
                continue;
            const xa = Math.round(ccx - tw / 2) - pad, ya = Math.round(ccy - th / 2) - pad;
            const r = search(f, await tpl(tw, th), tw, th, xa, xa + 2 * pad, ya, ya + 2 * pad);
            if (r && r.s >= MATCH_NCC && (!hit || r.s > hit.ncc))
                hit = { regId: im.record.regId, n: im.n, ncc: +r.s.toFixed(3), scale: +s.toFixed(3), retainedPct: +Math.min(100, (100 * (up.w / s) * (up.h / s)) / (rw * rh)).toFixed(1),
                    left: Math.round(r.x / f.cx), top: Math.round(r.y / f.cy), width: Math.min(rw, Math.round(up.w / s)), height: Math.min(rh, Math.round(up.h / s)), regW: rw, regH: rh };
        }
        if (hit)
            break; // candidates are ordered by coarse score
    }
    return hit;
}
