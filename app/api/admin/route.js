import { NextResponse } from "next/server";
import { audit, mutate, requireAdmin, route } from "@/lib/auth";
import { auditChainOk, load } from "@/lib/db";
import { HttpError } from "@/lib/util";
export const dynamic = "force-dynamic";
export const GET = route(async () => {
    await requireAdmin();
    const db = await load(), count = (s) => db.verifications.filter(v => v.status === s).length;
    const failedLogins = db.audit.filter(a => a.action === "login.failed").length;
    const byIp = new Map();
    for (const v of db.verifications)
        if (v.status !== "VERIFIED")
            byIp.set(v.ip, (byIp.get(v.ip) || 0) + 1);
    return NextResponse.json({
        stats: { users: db.users.length, images: db.images.length, verifications: db.verifications.length, verified: count("VERIFIED"), modified: count("MODIFIED"), unregistered: count("UNREGISTERED"), inconclusive: count("INCONCLUSIVE"), potentialMatch: count("POTENTIAL_MATCH"), failedLogins, suspiciousIps: [...byIp.values()].filter(n => n >= 10).length },
        users: db.users.map(u => ({ id: u.id, name: u.name, email: u.email, role: u.role, active: u.active, verified: u.verified, at: u.at, images: db.images.filter(i => i.userId === u.id).length })),
        images: db.images.slice(-200).reverse().map(i => ({ id: i.id, regId: i.record.regId, name: i.name, owner: db.users.find(u => u.id === i.userId)?.name, at: i.record.at, alg: i.record.alg, psnr: i.psnr })),
        verifications: db.verifications.slice(-150).reverse().map(v => ({ id: v.id, at: v.at, status: v.status, kind: v.kind, regId: v.regId, ip: v.ip, userId: v.userId })),
        audit: db.audit.slice(-200).reverse().map(a => ({ t: a.t, action: a.action, userId: a.userId, details: a.details })),
        auditChainOk: auditChainOk(db),
    });
});
/** Suspend or reactivate an account. Suspending also invalidates its sessions. */
export const PATCH = route(async (req) => {
    const me = await requireAdmin(), b = await req.json().catch(() => null);
    if (!b || typeof b.userId !== "string" || typeof b.active !== "boolean")
        throw new HttpError("Invalid request.");
    if (b.userId === me.id)
        throw new HttpError("You cannot suspend your own account.");
    await mutate(db => {
        const u = db.users.find(x => x.id === b.userId);
        if (!u)
            throw new HttpError("No such user.", 404);
        u.active = b.active;
        u.tv++;
        audit(db, b.active ? "admin.reactivate" : "admin.suspend", me.id, { target: u.id, email: u.email });
    });
    return NextResponse.json({ ok: true });
});
