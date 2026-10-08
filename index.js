const { onCall, HttpsError } = require("firebase-functions/v2/https");
const { defineSecret } = require("firebase-functions/params");
const admin = require("firebase-admin");
const crypto = require("crypto");

admin.initializeApp();
const db = admin.firestore();

// SHA-256 (hex) of your access code, stored in Secret Manager. Never in the web page.
const ACCESS_CODE_HASH = defineSecret("ACCESS_CODE_HASH");

const WINDOW_MS = 15 * 60 * 1000;
const MAX_FAILS = 5;
const ENFORCE_APP_CHECK = false; // set true after enabling App Check (see SETUP.md)

exports.verifyAccessCode = onCall(
  { secrets: [ACCESS_CODE_HASH], enforceAppCheck: ENFORCE_APP_CHECK, maxInstances: 10 },
  async (request) => {
    const code = String((request.data && request.data.code) || "").trim();
    if (!code || code.length > 128) throw new HttpsError("invalid-argument", "Missing access code.");

    // Per-IP brute-force lockout
    const ip = request.rawRequest.ip || "unknown";
    const ref = db.doc(`_rateLimits/${crypto.createHash("sha256").update(ip).digest("hex")}`);
    const snap = await ref.get();
    const rl = snap.data();
    if (rl && Date.now() - rl.start < WINDOW_MS && rl.fails >= MAX_FAILS) {
      throw new HttpsError("resource-exhausted", "Too many attempts.");
    }

    const given = crypto.createHash("sha256").update(code).digest();
    const expected = Buffer.from(ACCESS_CODE_HASH.value().trim(), "hex");
    const ok = expected.length === given.length && crypto.timingSafeEqual(given, expected);

    if (!ok) {
      await db.runTransaction(async (t) => {
        const s = (await t.get(ref)).data();
        const fresh = !s || Date.now() - s.start >= WINDOW_MS;
        t.set(ref, { start: fresh ? Date.now() : s.start, fails: fresh ? 1 : s.fails + 1 });
      });
      throw new HttpsError("permission-denied", "Invalid access code.");
    }

    await ref.delete().catch(() => {});
    const uid = `code_${crypto.randomUUID()}`;
    const token = await admin.auth().createCustomToken(uid, { accessCode: true });
    return { token };
  }
);
