import sharp from "sharp";
import { luma, sharpIn } from "./wm.js";
/* ---------- semi-fragile block fingerprints (tamper localisation) ----------
 * The image is tiled into 32x32 blocks; each block is summarised by a 4x4 grid of mean luminance values (16 bytes).
 * A block is "changed" when any of its 16 means moved by more than T grey levels. Re-encoding (JPEG), tiny noise and the
 * watermark itself move means by only a few levels, while inserted/removed/pasted content moves them a lot.
 */
export const BLK = 32, T = 14;
export const gridOf = (w, h) => ({ gw: Math.ceil(w / BLK), gh: Math.ceil(h / BLK) });
export function fingerprint(img) {
    const { w, h } = img, { gw, gh } = gridOf(w, h), Y = luma(img), out = new Uint8Array(gw * gh * 16);
    for (let by = 0; by < gh; by++)
        for (let bx = 0; bx < gw; bx++) {
            const x0 = bx * BLK, y0 = by * BLK, bw = Math.min(BLK, w - x0), bh = Math.min(BLK, h - y0), o = (by * gw + bx) * 16;
            for (let sy = 0; sy < 4; sy++)
                for (let sx = 0; sx < 4; sx++) {
                    const ya = Math.floor((sy * bh) / 4), yb = Math.max(Math.floor(((sy + 1) * bh) / 4), ya + 1);
                    const xa = Math.floor((sx * bw) / 4), xb = Math.max(Math.floor(((sx + 1) * bw) / 4), xa + 1);
                    let s = 0, c = 0;
                    for (let y = ya; y < Math.min(yb, bh); y++)
                        for (let x = xa; x < Math.min(xb, bw); x++) {
                            s += Y[(y0 + y) * w + x0 + x];
                            c++;
                        }
                    out[o + sy * 4 + sx] = Math.round(s / Math.max(1, c));
                }
        }
    return out;
}
/** Indices of blocks whose fingerprint differs by more than T. */
export function changedBlocks(a, b) {
    const bad = [], n = Math.min(a.length, b.length) / 16;
    for (let i = 0; i < n; i++) {
        let m = 0;
        for (let j = 0; j < 16; j++)
            m = Math.max(m, Math.abs(a[i * 16 + j] - b[i * 16 + j]));
        if (m > T)
            bad.push(i);
    }
    return bad;
}
/* ---------- perceptual hash (pHash): 32x32 grey -> DCT -> 8x8 low frequencies -> bits above the median ---------- */
const C32 = (() => { const m = new Float64Array(32 * 32); for (let u = 0; u < 32; u++)
    for (let x = 0; x < 32; x++)
        m[u * 32 + x] = Math.cos(((2 * x + 1) * u * Math.PI) / 64); return m; })();
export async function phash(img) {
    const { data } = await sharp(Buffer.from(img.rgb.buffer, img.rgb.byteOffset, img.rgb.length), { raw: { width: img.w, height: img.h, channels: 3 } })
        .resize(32, 32, { fit: "fill", kernel: "lanczos3" }).greyscale().raw().toBuffer({ resolveWithObject: true });
    const tmp = new Float64Array(8 * 32), co = new Float64Array(64);
    for (let y = 0; y < 32; y++)
        for (let u = 0; u < 8; u++) {
            let s = 0;
            for (let x = 0; x < 32; x++)
                s += data[y * 32 + x] * C32[u * 32 + x];
            tmp[u * 32 + y] = s;
        }
    for (let v = 0; v < 8; v++)
        for (let u = 0; u < 8; u++) {
            let s = 0;
            for (let y = 0; y < 32; y++)
                s += tmp[u * 32 + y] * C32[v * 32 + y];
            co[v * 8 + u] = s;
        }
    const sorted = Array.from(co.slice(1)).sort((a, b) => a - b), med = (sorted[31] + sorted[32]) / 2;
    let hex = "";
    for (let i = 0; i < 64; i += 4)
        hex += ((co[i] > med ? 8 : 0) | (co[i + 1] > med ? 4 : 0) | (co[i + 2] > med ? 2 : 0) | (co[i + 3] > med ? 1 : 0)).toString(16);
    return hex;
}
function parseExif(b) {
    const out = {};
    try {
        const o = b.toString("latin1", 0, 4) === "Exif" ? 6 : 0, bo = b.toString("latin1", o, o + 2), le = bo === "II";
        if (!le && bo !== "MM")
            return out;
        const u16 = (p) => (le ? b.readUInt16LE(o + p) : b.readUInt16BE(o + p));
        const u32 = (p) => (le ? b.readUInt32LE(o + p) : b.readUInt32BE(o + p));
        const SZ = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1 };
        const ifd = (at, handle) => {
            const n = Math.min(u16(at), 300);
            for (let i = 0; i < n; i++) {
                const e = at + 2 + i * 12, tag = u16(e), type = u16(e + 2), cnt = u32(e + 4), sz = (SZ[type] || 1) * cnt;
                handle(tag, type, cnt, sz <= 4 ? e + 8 : u32(e + 8));
            }
        };
        const str = (vp, cnt) => b.toString("latin1", o + vp, o + vp + cnt).replace(/\0.*$/s, "").trim();
        let exifPtr = 0;
        ifd(u32(4), (tag, type, cnt, vp) => {
            if (tag === 0x010f)
                out.make = str(vp, cnt);
            else if (tag === 0x0110)
                out.model = str(vp, cnt);
            else if (tag === 0x0131)
                out.software = str(vp, cnt);
            else if (tag === 0x0132)
                out.datetime = str(vp, cnt);
            else if (tag === 0x0112 && type === 3)
                out.orientation = u16(vp);
            else if (tag === 0x8825)
                out.gps = true;
            else if (tag === 0x8769)
                exifPtr = u32(vp);
        });
        if (exifPtr)
            ifd(exifPtr, (tag, _t, cnt, vp) => { if (tag === 0x9003)
                out.datetimeOriginal = str(vp, cnt); });
    }
    catch { /* truncated or malformed EXIF: return what was read */ }
    return out;
}
export async function metaOf(buf) {
    const m = await sharpIn(buf).metadata();
    return { format: m.format, width: m.width, height: m.height, space: m.space, ...(m.exif ? parseExif(m.exif) : {}) };
}
/** Human-readable differences between the registered original's metadata and an uploaded file's metadata. */
export function metaChanges(reg, up) {
    const out = [], hasExif = (m) => !!(m.make || m.model || m.datetime || m.datetimeOriginal || m.software);
    if (hasExif(reg) && !hasExif(up))
        out.push("The uploaded file has no camera metadata (it was stripped or the file was re-created).");
    for (const [k, label] of [["make", "Camera make"], ["model", "Camera model"], ["datetimeOriginal", "Capture time"], ["software", "Software"]])
        if (reg[k] && up[k] && reg[k] !== up[k])
            out.push(`${label} differs from the registered original.`);
    if (up.software && !reg.software)
        out.push(`Uploaded file names editing software: ${up.software}.`);
    return out;
}
/** JPEG data-URL of the (registered-geometry) image with changed blocks tinted red, downscaled to <= 900px wide. */
export async function heatmap(img, bad) {
    const { gw } = gridOf(img.w, img.h), s = Math.min(1, 900 / img.w), w = Math.max(1, Math.round(img.w * s)), h = Math.max(1, Math.round(img.h * s));
    const { data } = await sharp(Buffer.from(img.rgb.buffer, img.rgb.byteOffset, img.rgb.length), { raw: { width: img.w, height: img.h, channels: 3 } })
        .resize(w, h, { fit: "fill" }).raw().toBuffer({ resolveWithObject: true });
    const px = new Uint8Array(data.buffer, data.byteOffset, data.length);
    for (const i of bad) {
        const x0 = Math.floor((i % gw) * BLK * s), y0 = Math.floor(Math.floor(i / gw) * BLK * s), x1 = Math.min(w, Math.ceil(((i % gw) + 1) * BLK * s)), y1 = Math.min(h, Math.ceil((Math.floor(i / gw) + 1) * BLK * s));
        for (let y = y0; y < y1; y++)
            for (let x = x0; x < x1; x++) {
                const p = (y * w + x) * 3;
                px[p] = Math.round(px[p] * 0.45 + 255 * 0.55);
                px[p + 1] = Math.round(px[p + 1] * 0.45);
                px[p + 2] = Math.round(px[p + 2] * 0.45);
            }
    }
    const jpg = await sharp(Buffer.from(px.buffer, px.byteOffset, px.length), { raw: { width: w, height: h, channels: 3 } }).jpeg({ quality: 72 }).toBuffer();
    return "data:image/jpeg;base64," + jpg.toString("base64");
}
/**
 * Low-resolution previews for a content match (so the public report cannot be used to download the protected file):
 * the registered image (<= 640 px wide, JPEG) with the matched region outlined, and the uploaded image (<= 400 px).
 */
export async function matchPreviews(png, m, up) {
    const k = Math.min(1, 640 / m.regW), w = Math.max(1, Math.round(m.regW * k)), h = Math.max(1, Math.round(m.regH * k));
    const x = Math.round(m.left * k), y = Math.round(m.top * k), bw = Math.max(2, Math.round(m.width * k)), bh = Math.max(2, Math.round(m.height * k));
    const box = Buffer.from(`<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}"><rect x="${x}" y="${y}" width="${bw}" height="${bh}" fill="rgba(255,60,60,0.18)" stroke="#ff3c3c" stroke-width="3"/></svg>`);
    const orig = await sharp(png).resize(w, h, { fit: "fill" }).composite([{ input: box }]).jpeg({ quality: 72 }).toBuffer();
    const u = Math.min(1, 400 / up.w), upl = await sharp(Buffer.from(up.rgb.buffer, up.rgb.byteOffset, up.rgb.length), { raw: { width: up.w, height: up.h, channels: 3 } })
        .resize(Math.max(1, Math.round(up.w * u)), Math.max(1, Math.round(up.h * u)), { fit: "fill" }).jpeg({ quality: 72 }).toBuffer();
    const url = (b) => "data:image/jpeg;base64," + b.toString("base64");
    return { originalPreview: url(orig), uploadPreview: url(upl) };
}
