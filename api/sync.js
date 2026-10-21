/**
 * Vercel Serverless Function: /api/sync (Security-Hardened v2)
 *
 * 보안 패치 적용 내역:
 * 1) 프론트엔드(index.html)에서 Supabase Anon Key 완전 은닉 및 서버 단독 통신 구조화
 * 2) IP 기반 슬라이딩 윈도우 레이트 리미팅 (DDoS / 무차별 대입 공격 차단)
 * 3) 프로토타입 오염(__proto__, constructor) 원천 차단 및 엄격한 스키마·길이·좌표 검증
 * 4) 서버 측 SHA-256 해시 기반 편집 잠금(PIN Lock) 검증 (비밀번호 불일치 시 403 차단 및 해시값 외부 비노출)
 * 5) CSRF 방어용 커스텀 헤더 검증 및 내부 스택 트레이스 정보 노출 차단
 */

const crypto = require("crypto");

const SUPABASE_URL =
  process.env.SUPABASE_URL || "https://abjspnuohxouufkdjefs.supabase.co";
const SUPABASE_ANON_KEY =
  process.env.SUPABASE_ANON_KEY ||
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFianNwbnVvaHhvdXVma2RqZWZzIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODkzMDA5NzcsImV4cCI6MjEwNDg3Njk3N30.hVL3TRPwA1xalf1Tb2LiKJ58Q_DgBc5RWwFs2AfR890";

const SYNC_ROW_KEY = "JAPAN_TRAVEL_PLANNER_635";
const PIN_HASH_SALT = "JP_TRAVEL_PLANNER_635_SECURITY_SALT_v2";

let memoryFallback = null;

// 🛡️ IP별 요청 속도 제한 (Rate Limiter) 및 PIN 오입력 차단기
const rateLimitStore = new Map();
const pinFailStore = new Map();

function getClientIp(req) {
  const xff = req.headers["x-forwarded-for"];
  if (typeof xff === "string" && xff.length > 0) {
    return xff.split(",")[0].trim();
  }
  return req.socket?.remoteAddress || "unknown";
}

function checkRateLimit(ip, method) {
  const now = Date.now();
  const windowMs = 60 * 1000;
  const maxReq = method === "POST" ? 30 : 90;

  let record = rateLimitStore.get(ip);
  if (!record || now - record.windowStart > windowMs) {
    record = { windowStart: now, count: 0 };
  }
  record.count += 1;
  rateLimitStore.set(ip, record);

  if (rateLimitStore.size > 2000) {
    for (const [k, v] of rateLimitStore.entries()) {
      if (now - v.windowStart > windowMs) rateLimitStore.delete(k);
    }
  }
  return record.count <= maxReq;
}

function isIpBlockedForPin(ip) {
  const rec = pinFailStore.get(ip);
  if (!rec) return false;
  if (Date.now() - rec.lastFail > 5 * 60 * 1000) {
    pinFailStore.delete(ip);
    return false;
  }
  return rec.fails >= 5;
}

function recordPinFailure(ip) {
  const now = Date.now();
  const rec = pinFailStore.get(ip) || { fails: 0, lastFail: now };
  if (now - rec.lastFail > 5 * 60 * 1000) {
    rec.fails = 0;
  }
  rec.fails += 1;
  rec.lastFail = now;
  pinFailStore.set(ip, rec);
}

function clearPinFailure(ip) {
  pinFailStore.delete(ip);
}

function hashPinCode(rawPin) {
  if (!rawPin || typeof rawPin !== "string") return "";
  return crypto
    .createHash("sha256")
    .update(`${PIN_HASH_SALT}:${rawPin.trim()}`)
    .digest("hex");
}

function safeTimingEqualHex(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length || a.length === 0) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
  } catch {
    return false;
  }
}

// 🧹 입력 문자열 정제 (제어문자 제거 및 최대 길이 제한)
function cleanString(val, maxLen = 200, fallback = "") {
  if (typeof val !== "string") return fallback;
  return val
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "")
    .trim()
    .slice(0, maxLen);
}

function cleanMultilineString(val, maxLen = 5000, fallback = "") {
  if (typeof val !== "string") return fallback;
  return val
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "")
    .slice(0, maxLen);
}

function clampNumber(val, min, max, fallback) {
  const num = Number(val);
  if (!Number.isFinite(num)) return fallback;
  return Math.min(max, Math.max(min, num));
}

// 🛡️ 스키마 검증 및 정제 (XSS / JSON 폭탄 / 프로토타입 오염 방지)
function sanitizeSyncPayload(raw, existingLockHash = "") {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("Invalid payload object");
  }

  const rawPins = Array.isArray(raw.pins) ? raw.pins.slice(0, 100) : [];
  const pins = [];

  for (const p of rawPins) {
    if (!p || typeof p !== "object") continue;
    const lat = Number(p.lat);
    const lng = Number(p.lng);
    if (!Number.isFinite(lat) || !Number.isFinite(lng)) continue;
    if (Math.abs(lat) > 90 || Math.abs(lng) > 180) continue;

    const rawItems = Array.isArray(p.items) ? p.items.slice(0, 100) : [];
    const items = rawItems
      .filter((it) => it && typeof it === "object")
      .map((it, idx) => ({
        id: cleanString(String(it.id || `item-${idx}`), 64, `item-${idx}`).replace(
          /[^a-zA-Z0-9_-]/g,
          ""
        ),
        title: cleanString(it.title, 100, "지출 항목"),
        price: Math.round(clampNumber(it.price, 0, 1000000000, 0)),
        yen: Math.round(clampNumber(it.yen, 0, 100000000, 0)),
        bought: Boolean(it.bought),
      }));

    let spendInfo = null;
    if (p.spendInfo && typeof p.spendInfo === "object") {
      spendInfo = {
        minYen: Math.round(clampNumber(p.spendInfo.minYen, 0, 10000000, 1000)),
        maxYen: Math.round(clampNumber(p.spendInfo.maxYen, 0, 10000000, 2500)),
        avgYen: Math.round(clampNumber(p.spendInfo.avgYen, 0, 10000000, 1500)),
        label: cleanString(p.spendInfo.label, 60, "¥1,000 ~ ¥2,500"),
        desc: cleanString(p.spendInfo.desc, 120, ""),
        recommendedTitle: cleanString(p.spendInfo.recommendedTitle, 60, "1인 평균 지출"),
      };
    }

    pins.push({
      id: cleanString(String(p.id || `pin-${Date.now()}`), 64, `pin-${Date.now()}`).replace(
        /[^a-zA-Z0-9_-]/g,
        ""
      ),
      name: cleanString(p.name, 120, "여행 장소"),
      category: cleanString(p.category, 40, "📸 명소·포토존"),
      address: cleanString(p.address, 300, ""),
      lat,
      lng,
      completed: Boolean(p.completed),
      memo: cleanMultilineString(p.memo, 2000, ""),
      customTransitMinutes:
        p.customTransitMinutes !== null && p.customTransitMinutes !== undefined
          ? Math.round(clampNumber(p.customTransitMinutes, 0, 10000, 0)) || null
          : null,
      spendInfo,
      items,
    });
  }

  const rawNotes = Array.isArray(raw.notes) ? raw.notes.slice(0, 30) : [];
  const notes = rawNotes
    .filter((n) => n && typeof n === "object")
    .map((n, idx) => ({
      id: cleanString(String(n.id || `note-${idx}`), 64, `note-${idx}`).replace(
        /[^a-zA-Z0-9_-]/g,
        ""
      ),
      title: cleanString(n.title, 100, `📝 메모장 #${idx + 1}`),
      content: cleanMultilineString(n.content, 20000, ""),
      updatedAt: cleanString(n.updatedAt, 60, new Date().toLocaleString("ko-KR")),
    }));

  const rawChecklist = Array.isArray(raw.checklist) ? raw.checklist.slice(0, 200) : [];
  const checklist = rawChecklist
    .filter((c) => c && typeof c === "object")
    .map((c, idx) => ({
      id: cleanString(String(c.id || `chk-${idx}`), 64, `chk-${idx}`).replace(
        /[^a-zA-Z0-9_-]/g,
        ""
      ),
      text: cleanString(c.text, 200, "체크 항목"),
      done: Boolean(c.done),
    }));

  return {
    pins,
    tripTitle: cleanString(raw.tripTitle, 80, "우리의 일본 여행 ✈️"),
    exchangeRate: clampNumber(raw.exchangeRate, 0.5, 100, 9.05),
    peopleCount: Math.round(clampNumber(raw.peopleCount, 1, 50, 2)),
    notes,
    checklist,
    explicitlyCleared: Boolean(raw.explicitlyCleared),
    forceOverwrite: Boolean(raw.forceOverwrite),
    updatedAt: clampNumber(raw.updatedAt, 0, Date.now() + 60000, Date.now()),
    clientId: cleanString(raw.clientId, 64, "unknown").replace(/[^a-zA-Z0-9_-]/g, ""),
    lockHash: existingLockHash || "",
  };
}

function stripSensitiveFieldsForClient(data) {
  if (!data || typeof data !== "object") return data;
  const { lockHash, ...safeData } = data;
  return {
    ...safeData,
    isLocked: Boolean(lockHash),
  };
}

function getSupabaseHeaders(extra = {}) {
  return {
    apikey: SUPABASE_ANON_KEY,
    Authorization: `Bearer ${SUPABASE_ANON_KEY}`,
    "Content-Type": "application/json",
    ...extra,
  };
}

async function fetchFromSupabase() {
  const endpoint = `${SUPABASE_URL}/rest/v1/couple_calendar?date=eq.${encodeURIComponent(
    SYNC_ROW_KEY
  )}&select=*`;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 6000);

  try {
    const res = await fetch(endpoint, {
      method: "GET",
      headers: getSupabaseHeaders({ "Cache-Control": "no-cache" }),
      signal: controller.signal,
    });

    if (!res.ok) {
      throw new Error(`Supabase GET status ${res.status}`);
    }

    const rows = await res.json();
    if (!Array.isArray(rows) || rows.length === 0) {
      return null;
    }

    const row = rows[0];
    if (row.hae_shift && typeof row.hae_shift === "object") {
      return row.hae_shift;
    }
    if (row.hae_memo && typeof row.hae_memo === "string") {
      try {
        return JSON.parse(row.hae_memo);
      } catch {
        return null;
      }
    }
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function saveToSupabase(payload) {
  const endpoint = `${SUPABASE_URL}/rest/v1/couple_calendar?on_conflict=date`;
  const rowBody = {
    date: SYNC_ROW_KEY,
    memo: "",
    hae_shift: payload,
    hae_memo: JSON.stringify(payload),
  };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 6000);

  try {
    const res = await fetch(endpoint, {
      method: "POST",
      headers: getSupabaseHeaders({
        Prefer: "resolution=merge-duplicates,return=minimal",
      }),
      body: JSON.stringify(rowBody),
      signal: controller.signal,
    });

    if (!res.ok) {
      throw new Error(`Supabase UPSERT status ${res.status}`);
    }
    return true;
  } finally {
    clearTimeout(timer);
  }
}

module.exports = async function handler(req, res) {
  // 🔒 보안 응답 헤더 설정
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");

  const origin = req.headers.origin || "";
  if (origin) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  } else {
    res.setHeader("Access-Control-Allow-Origin", "*");
  }
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, X-Requested-With, X-Planner-Pin"
  );

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  const clientIp = getClientIp(req);
  if (!checkRateLimit(clientIp, req.method)) {
    return res.status(429).json({
      ok: false,
      error: "요청이 너무 많습니다. 잠시 후 다시 시도해주세요.",
    });
  }

  try {
    if (req.method === "GET") {
      try {
        const cloudData = await fetchFromSupabase();
        if (cloudData) {
          memoryFallback = cloudData;
          return res.status(200).json(stripSensitiveFieldsForClient(cloudData));
        }
      } catch {
        if (memoryFallback) {
          return res.status(200).json(stripSensitiveFieldsForClient(memoryFallback));
        }
      }
      return res.status(200).json(
        memoryFallback
          ? stripSensitiveFieldsForClient(memoryFallback)
          : {
              pins: [],
              notes: [],
              checklist: [],
              empty: true,
              isLocked: false,
              updatedAt: 0,
            }
      );
    }

    if (req.method === "POST") {
      // CSRF 방어: 전용 커스텀 헤더 확인
      const requestedWith = req.headers["x-requested-with"];
      if (requestedWith !== "SmartTravelPlanner-v2") {
        return res.status(403).json({
          ok: false,
          error: "승인되지 않은 외부 요청입니다 (CSRF Blocked).",
        });
      }

      if (isIpBlockedForPin(clientIp)) {
        return res.status(429).json({
          ok: false,
          locked: true,
          error: "비밀번호 입력 실패 횟수를 초과했습니다. 5분 후 다시 시도해주세요.",
        });
      }

      const rawBodyStr =
        typeof req.body === "string" ? req.body : JSON.stringify(req.body || {});
      if (rawBodyStr.length > 250000) {
        return res.status(413).json({
          ok: false,
          error: "데이터 크기가 허용 한도(250KB)를 초과했습니다.",
        });
      }

      let body = {};
      try {
        body = typeof req.body === "string" ? JSON.parse(req.body) : req.body || {};
      } catch {
        return res.status(400).json({ ok: false, error: " 잘못된 JSON 형식입니다." });
      }

      // 현재 클라우드 데이터 및 잠금 상태 조회
      let existing = null;
      try {
        existing = await fetchFromSupabase();
      } catch {
        existing = memoryFallback;
      }

      const currentLockHash =
        existing && typeof existing.lockHash === "string" ? existing.lockHash : "";
      const providedPin = cleanString(
        req.headers["x-planner-pin"] || body.authPin || "",
        32,
        ""
      );
      const providedHash = providedPin ? hashPinCode(providedPin) : "";

      // 🔒 액션 1: 비밀번호 검증 전용 요청 (verifyPinOnly)
      if (body.action === "verifyPin") {
        if (!currentLockHash) {
          return res.status(200).json({ ok: true, isLocked: false, verified: true });
        }
        if (safeTimingEqualHex(providedHash, currentLockHash)) {
          clearPinFailure(clientIp);
          return res.status(200).json({ ok: true, isLocked: true, verified: true });
        } else {
          recordPinFailure(clientIp);
          return res.status(403).json({
            ok: false,
            locked: true,
            verified: false,
            error: "보안 비밀번호가 일치하지 않습니다.",
          });
        }
      }

      // 🔒 기존 잠금이 설정되어 있는 경우 모든 수정/잠금해제 요청에 대해 비밀번호 검증 필수!
      if (currentLockHash) {
        if (!safeTimingEqualHex(providedHash, currentLockHash)) {
          recordPinFailure(clientIp);
          return res.status(403).json({
            ok: false,
            locked: true,
            error: "🔒 보안 잠금이 켜져 있습니다. 상단 자물쇠 또는 설정에서 비밀번호를 입력해주세요.",
          });
        }
        clearPinFailure(clientIp);
      }

      // 🔒 액션 2: 새 비밀번호 설정 또는 잠금 해제 요청 (setPin / clearPin)
      let nextLockHash = currentLockHash;
      if (body.action === "setPin") {
        const newPin = cleanString(body.newPin || "", 32, "");
        if (newPin.length < 4) {
          return res.status(400).json({
            ok: false,
            error: "비밀번호는 최소 4자리 이상이어야 합니다.",
          });
        }
        nextLockHash = hashPinCode(newPin);
      } else if (body.action === "clearPin") {
        nextLockHash = "";
      }

      // 빈 초기 기기가 기존 클라우드 데이터를 덮어쓰는 현상 방지
      const incomingPins = Array.isArray(body.pins) ? body.pins : [];
      if (
        incomingPins.length === 0 &&
        !body.explicitlyCleared &&
        !body.forceOverwrite &&
        body.action !== "setPin" &&
        body.action !== "clearPin"
      ) {
        if (existing && Array.isArray(existing.pins) && existing.pins.length > 0) {
          return res.status(200).json({
            ok: false,
            skippedEmptyOverwrite: true,
            cloudData: stripSensitiveFieldsForClient(existing),
          });
        }
      }

      const sanitizedPayload = sanitizeSyncPayload(body, nextLockHash);

      memoryFallback = sanitizedPayload;
      await saveToSupabase(sanitizedPayload);

      return res.status(200).json({
        ok: true,
        isLocked: Boolean(nextLockHash),
        updatedAt: sanitizedPayload.updatedAt,
        storage: "supabase-couple-calendar-secured",
      });
    }

    return res.status(405).json({ error: "Method not allowed" });
  } catch {
    return res.status(500).json({
      ok: false,
      error: "일시적인 동기화 서버 오류가 발생했습니다.",
    });
  }
};
