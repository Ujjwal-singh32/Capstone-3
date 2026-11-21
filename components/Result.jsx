"use client";
import { KIND_LABEL, STATUS_LABEL } from "@/lib/labels";
import { when } from "@/lib/client";
const E = (k) => (k ? KIND_LABEL[k] : "");
/** Verification report, shared by the main page and the public /verify/[regId] page. */
export default function Result({ r }) {
    const t = r.tamper;
    return (<div className="card" aria-live="polite">
      <div className={`status ${r.status}`}>{STATUS_LABEL[r.status]}</div>
      {r.reason && <p>{r.reason}</p>}
      {r.kind && <p>{E(r.kind)}{r.kind === "cropped" && r.retainedPct ? ` About ${r.retainedPct}% of the registered image area remains.` : ""}{r.align ? ` Geometry: ${r.align}.` : ""}</p>}
      <dl>
        <dt>Verification ID</dt><dd>{r.id}</dd>
        <dt>Registration</dt><dd>{r.regId || "none recovered"}</dd>
        <dt>Registered owner</dt><dd>{r.owner || "—"}</dd>
        <dt>Registered at</dt><dd>{r.registeredAt ? when(r.registeredAt) : "—"}</dd>
        <dt>Watermark authentic</dt><dd>{r.cryptoValid ? `yes (AES-256-GCM tag valid${r.alg ? `, ${r.alg.toUpperCase()}` : ""})` : "no"}</dd>
        <dt>Record signature</dt><dd>{r.regId ? (r.recordSignatureValid ? "valid (Ed25519)" : "INVALID") : "—"}</dd>
        <dt>Registration signing key</dt><dd>{r.keyFingerprint || "—"}</dd>
        <dt>This server signing key</dt><dd>{r.serverKeyFingerprint || "—"}</dd>
        <dt>File SHA-256</dt><dd className="mono">{r.hash}</dd>
        {r.registeredHash && <><dt>Registered SHA-256</dt><dd className="mono">{r.registeredHash}</dd></>}
        <dt>Checked</dt><dd>{when(r.at)}</dd>
      </dl>
      {t && t.bad.length > 0 && <>
        <p><b>{t.pct}%</b> of the 32 px blocks ({t.bad.length} of {t.gw * t.gh}) differ from the registered copy. This is coarse, block-level evidence of where content changed; it does not identify what was done.</p>
        {r.heatmap && <img className="heat" src={r.heatmap} alt="Image with changed regions highlighted in red"/>}
      </>}
      {t && t.bad.length === 0 && <p>No region differs materially from the registered copy.</p>}
      {r.patternDetected && <p>A watermark-like pattern was detected, so the image probably derives from a protected one, but it could not be authenticated.</p>}
      {r.contentMatch && (() => { const c = r.contentMatch, g = c.region; return <>
        <p><b>Match detected: <a href={`/verify/${c.regId}`}>{c.regId}</a></b>{c.owner ? ` (registered by ${c.owner})` : ""}</p>
        <dl>
          <dt>Confidence (pixel similarity)</dt><dd>{c.confidence}% · {c.confidence >= 97 ? "very high" : c.confidence >= 93 ? "high" : "moderate"}</dd>
          <dt>Portion of registered image</dt><dd>{c.retainedPct}%{g && c.retainedPct < 97 ? ` (matched region ${g.width} x ${g.height} px at x=${g.left}, y=${g.top} of ${c.registeredSize[0]} x ${c.registeredSize[1]})` : ""}</dd>
        </dl>
        {(c.uploadPreview || c.originalPreview) && <div className="match">
          {c.uploadPreview && <figure><img src={c.uploadPreview} alt="The uploaded image"/><figcaption>Uploaded image{c.retainedPct < 97 ? " (the cropped part)" : ""}</figcaption></figure>}
          {c.originalPreview && <figure><img src={c.originalPreview} alt="Registered image with the matched region outlined"/><figcaption>Registered image{c.retainedPct < 97 ? ", matched region outlined in red" : ""} (low-resolution preview)</figcaption></figure>}
        </div>}
      </>; })()}
      {r.similar?.length > 0 && <>
        <p><b>Visually similar registered images</b> (perceptual hash; supporting evidence only, not proof of ownership):</p>
        <ul>{r.similar.map((s) => <li key={s.regId}><a href={`/verify/${s.regId}`}>{s.regId}</a> · Hamming distance {s.distance}/64</li>)}</ul>
      </>}
      {r.meta?.changes?.length > 0 && <><p><b>Metadata findings</b> (metadata is easily edited or removed):</p><ul>{r.meta.changes.map((c) => <li key={c}>{c}</li>)}</ul></>}
      {r.meta?.uploaded && (r.meta.uploaded.make || r.meta.uploaded.model || r.meta.uploaded.datetimeOriginal) &&
            <p className="dim">Uploaded file metadata: {[r.meta.uploaded.make, r.meta.uploaded.model, r.meta.uploaded.datetimeOriginal, r.meta.uploaded.gps ? "has GPS data" : ""].filter(Boolean).join(" · ")}</p>}
    </div>);
}
