/**
 * Vercel Serverless Function: /api/sync (Security-Hardened v3 — Full Entry Gate & Admin Vault)
 *
 * 보안 패치 적용 내역:
 * 1) 시작 페이지 전체 잠금 게이트: 유효한 접속 비밀번호 없이는 GET/POST 모두 여행 데이터를 절대 반환·수정하지 않음
 * 2) PBKDF2-HMAC-SHA512 (100,000회 반복 + 고유 Salt) 단방향 암호화 및 타이밍 공격 방어(crypto.timingSafeEqual)
 *    - 소스코드 어디에도 초기 비밀번호 및 관리자 비밀번호 평문이 존재하지 않음
 * 3) 비밀번호 5회 오류 시 해당 IP 자동 영구 차단 (메모리 + 클라우드 DB 이중 영구 기록)
 * 4) 관리자 전용 비밀번호 인증 시에만 열리는 [관리자 권한 페이지]에서 접속 허용 비밀번호 지정·추가·삭제 및 차단 IP 해제 지원
 * 5) 프로토타입 오염 방지, XSS 제어문자 정제, 250KB 용량 제한, 슬라이딩 윈도우 Rate Limiting 적용
 */

const crypto = require("crypto");

// NOTE: Vercel Environment Variables 설정이 필요합니다 (SUPABASE_URL, SUPABASE_ANON_KEY).
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;

const SYNC_ROW_KEY = "JAPAN_TRAVEL_PLANNER_635";

// 🔐 PBKDF2-HMAC-SHA512 (100,000 iterations) 보안 상수 — 평문 비밀번호는 코드에 일절 저장하지 않음
const PBKDF2_ITERATIONS = 100000;
const PBKDF2_KEYLEN = 64;
const PBKDF2_DIGEST = "sha512";

const DEFAULT_ENTRY_SALT = "JP635_ENTRY_DEFAULT_SALT_v3_99f1a4c8";
const DEFAULT_ENTRY_PBKDF2_HASH =
  "8e2f0d712822571d7b38aae78443f99b40ca70edbbcc664136d1b7654a2a9cddfa814f418de9f5b767f4e6ff9c0b6cd39623083473489d735ab0d1770ad6d954";

const ADMIN_MASTER_SALT = "JP635_ADMIN_MASTER_SALT_v3_e7b204d1";
const ADMIN_MASTER_PBKDF2_HASH =
  "b9930fbde86ad79e8c2d8b6c39ed23689c35d7a98a5eab5e21f67ec8e4fc6b28e0e83a8fbdc4fa9e43b5988f940542b04d27cafe5d4c3e45e7664e2daa8260f4";

const MAX_PIN_FAILS = 5;

let memoryFallback = null;

// 🛡️ IP별 요청 속도 제한 (Rate Limiter) 및 오입력/차단 메모리 캐시
const rateLimitStore = new Map();
const ipSecurityMemory = new Map();

function getClientIp(req) {
  const xff = req.headers["x-forwarded-for"];
  if (typeof xff === "string" && xff.length > 0) {
    return xff.split(",")[0].trim().slice(0, 64);
  }
  const realIp = req.headers["x-real-ip"];
  if (typeof realIp === "string" && realIp.length > 0) {
    return realIp.trim().slice(0, 64);
  }
  return (req.socket?.remoteAddress || "unknown").slice(0, 64);
}

function checkRateLimit(ip, method) {
  const now = Date.now();
  const windowMs = 60 * 1000;
  const maxReq = method === "POST" ? 40 : 90;

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

function derivePbkdf2Hex(rawPassword, salt) {
  if (typeof rawPassword !== "string" || !rawPassword || typeof salt !== "string" || !salt) {
    return "";
  }
  try {
    return crypto
      .pbkdf2Sync(rawPassword, salt, PBKDF2_ITERATIONS, PBKDF2_KEYLEN, PBKDF2_DIGEST)
      .toString("hex");
  } catch {
    return "";
  }
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

function maskPasswordHint(pw) {
  if (typeof pw !== "string") return "••••";
  const trimmed = pw.trim();
  if (trimmed.length <= 2) return "••••";
  if (trimmed.length <= 4) {
    return `${trimmed[0]}•••${trimmed[trimmed.length - 1]}`;
  }
  return `${trimmed.slice(0, 2)}${"•".repeat(Math.min(6, trimmed.length - 3))}${trimmed.slice(-1)}`;
}

function verifyAdminMasterKey(candidate) {
  if (typeof candidate !== "string") return false;
  const trimmed = candidate.trim();
  if (!trimmed) return false;
  const derived = derivePbkdf2Hex(trimmed, ADMIN_MASTER_SALT);
  return safeTimingEqualHex(derived, ADMIN_MASTER_PBKDF2_HASH);
}

function ensureSecurityConfig(existingObj) {
  const base =
    existingObj &&
    typeof existingObj === "object" &&
    existingObj.securityConfig &&
    typeof existingObj.securityConfig === "object"
      ? existingObj.securityConfig
      : {};

  let accessEntries = Array.isArray(base.accessEntries)
    ? base.accessEntries.filter(
        (e) =>
          e &&
          typeof e === "object" &&
          typeof e.salt === "string" &&
          typeof e.hash === "string" &&
          e.hash.length === 128
      )
    : [];

  if (accessEntries.length === 0) {
    accessEntries = [
      {
        id: "default-entry-key",
        label: "초기 지정 비밀번호",
        maskedHint: "•••••••• (암호화 보호됨)",
        salt: DEFAULT_ENTRY_SALT,
        hash: DEFAULT_ENTRY_PBKDF2_HASH,
        createdAt: "기본 보안 설정",
      },
    ];
  }

  const ipRecords =
    base.ipRecords && typeof base.ipRecords === "object" && !Array.isArray(base.ipRecords)
      ? { ...base.ipRecords }
      : {};

  // 메모리 캐시와 병합하여 서버리스 인스턴스 간 상태 동기화
  for (const [ip, memRec] of ipSecurityMemory.entries()) {
    const cloudRec = ipRecords[ip];
    if (!cloudRec || (memRec.fails || 0) > (cloudRec.fails || 0) || memRec.banned) {
      ipRecords[ip] = { ...memRec };
    }
  }
  for (const [ip, cloudRec] of Object.entries(ipRecords)) {
    if (cloudRec && typeof cloudRec === "object") {
      ipSecurityMemory.set(ip, { ...cloudRec });
    }
  }

  const now = Date.now();
  const inviteTickets = Array.isArray(base.inviteTickets)
    ? base.inviteTickets.filter(
        (t) =>
          t &&
          typeof t === "object" &&
          typeof t.ticket === "string" &&
          t.ticket.length >= 32 &&
          Number(t.expiresAt || 0) > now
      )
    : [];

  return {
    accessEntries,
    ipRecords,
    inviteTickets,
  };
}

function verifyAccessPassword(candidate, securityConfig) {
  if (typeof candidate !== "string") return false;
  const trimmed = candidate.trim();
  if (!trimmed) return false;

  // 1) 동적 난수 티켓 인증 (비밀번호 노출 없는 일회성/기간제 난수 토큰)
  const cleanTicket = trimmed.startsWith("ticket:") ? trimmed.slice(7).trim() : trimmed;
  if (cleanTicket.length >= 32) {
    const validTicket = (securityConfig?.inviteTickets || []).find(
      (t) => t.ticket === cleanTicket && Number(t.expiresAt || 0) > Date.now()
    );
    if (validTicket) return true;
  }

  const entries = Array.isArray(securityConfig?.accessEntries)
    ? securityConfig.accessEntries
    : [];

  for (const entry of entries) {
    const derived = derivePbkdf2Hex(trimmed, entry.salt);
    if (safeTimingEqualHex(derived, entry.hash)) {
      return true;
    }
  }

  // 관리자 마스터 비밀번호로도 입장 허용
  if (verifyAdminMasterKey(trimmed)) {
    return true;
  }

  return false;
}

function getIpStatus(ip, securityConfig) {
  const rec =
    securityConfig?.ipRecords?.[ip] ||
    ipSecurityMemory.get(ip) || {
      fails: 0,
      banned: false,
      bannedAt: null,
      lastAttemptAt: 0,
    };
  return {
    fails: Number(rec.fails) || 0,
    banned: Boolean(rec.banned) || (Number(rec.fails) || 0) >= MAX_PIN_FAILS,
    bannedAt: rec.bannedAt || null,
    lastAttemptAt: Number(rec.lastAttemptAt) || 0,
  };
}

function registerIpFailure(ip, securityConfig) {
  const current = getIpStatus(ip, securityConfig);
  const nextFails = current.fails + 1;
  const isNowBanned = nextFails >= MAX_PIN_FAILS;
  const updated = {
    fails: nextFails,
    banned: isNowBanned,
    bannedAt: isNowBanned
      ? current.bannedAt || new Date().toLocaleString("ko-KR")
      : null,
    lastAttemptAt: Date.now(),
  };
  securityConfig.ipRecords[ip] = updated;
  ipSecurityMemory.set(ip, updated);
  return updated;
}

function resetIpFailure(ip, securityConfig) {
  if (securityConfig?.ipRecords?.[ip]) {
    delete securityConfig.ipRecords[ip];
  }
  ipSecurityMemory.delete(ip);
}

function formatAdminClientPayload(securityConfig) {
  const accessEntries = (securityConfig.accessEntries || []).map((e, idx) => ({
    id: String(e.id || `pw-${idx}`),
    label: String(e.label || `허용 비밀번호 #${idx + 1}`),
    maskedHint: String(e.maskedHint || "••••"),
    createdAt: String(e.createdAt || ""),
  }));

  const bannedIps = Object.entries(securityConfig.ipRecords || {})
    .filter(([, rec]) => rec && (rec.banned || (rec.fails || 0) > 0))
    .map(([ip, rec]) => ({
      ip,
      fails: Number(rec.fails) || 0,
      banned: Boolean(rec.banned) || (Number(rec.fails) || 0) >= MAX_PIN_FAILS,
      bannedAt: rec.bannedAt || "-",
    }));

  return { accessEntries, bannedIps };
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

// 🛡️ 의미 있는 데이터 판별 및 병합 헬퍼 (데이터 유실 방지)
function hasMeaningfulNotes(notesList) {
  return (
    Array.isArray(notesList) &&
    notesList.some(
      (n) => n && typeof n.content === "string" && n.content.trim().length > 0
    )
  );
}

function hasMeaningfulChecklist(checkList) {
  return (
    Array.isArray(checkList) &&
    checkList.some(
      (c) => c && typeof c.text === "string" && c.text.trim().length > 0
    )
  );
}

function mergeNotes(baseList, incomingList) {
  const base = Array.isArray(baseList) ? baseList : [];
  const incoming = Array.isArray(incomingList) ? incomingList : [];

  const hasBase = hasMeaningfulNotes(base);
  const hasIncoming = hasMeaningfulNotes(incoming);

  if (hasBase && !hasIncoming) return base;
  if (!hasBase && hasIncoming) return incoming;
  if (!hasBase && !hasIncoming) return incoming.length > 0 ? incoming : base;

  const baseMap = new Map(base.map((n) => [String(n.id || ""), n]));
  const merged = [];

  for (const inNote of incoming) {
    const key = String(inNote.id || "");
    if (baseMap.has(key)) {
      const bNote = baseMap.get(key);
      const bContent = String(bNote.content || "").trim();
      const inContent = String(inNote.content || "").trim();

      if (inContent.length > 0 && bContent.length === 0) {
        merged.push(inNote);
      } else if (bContent.length > 0 && inContent.length === 0) {
        merged.push(bNote);
      } else {
        const bTime = Number(bNote.updatedAtMs || Date.parse(bNote.updatedAt) || 0);
        const inTime = Number(inNote.updatedAtMs || Date.parse(inNote.updatedAt) || 0);
        if (Math.abs(inTime - bTime) > 3000) {
          merged.push(inTime > bTime ? inNote : bNote);
        } else {
          merged.push(inContent.length >= bContent.length ? inNote : bNote);
        }
      }
      baseMap.delete(key);
    } else {
      merged.push(inNote);
    }
  }

  for (const [, bNote] of baseMap.entries()) {
    merged.push(bNote);
  }

  return merged.slice(0, 30);
}

function mergeChecklist(baseList, incomingList) {
  const base = Array.isArray(baseList) ? baseList : [];
  const incoming = Array.isArray(incomingList) ? incomingList : [];

  const hasBase = hasMeaningfulChecklist(base);
  const hasIncoming = hasMeaningfulChecklist(incoming);

  if (hasBase && !hasIncoming) return base;
  if (!hasBase && hasIncoming) return incoming;
  if (!hasBase && !hasIncoming) return incoming.length > 0 ? incoming : base;

  const baseMap = new Map(base.map((c) => [String(c.id || ""), c]));
  const merged = [];

  for (const inItem of incoming) {
    const key = String(inItem.id || "");
    if (baseMap.has(key)) {
      const bItem = baseMap.get(key);
      merged.push({
        id: key,
        text: (inItem.text || "").length >= (bItem.text || "").length ? inItem.text : bItem.text,
        done: Boolean(inItem.done),
      });
      baseMap.delete(key);
    } else {
      merged.push(inItem);
    }
  }

  for (const [, bItem] of baseMap.entries()) {
    merged.push(bItem);
  }

  return merged.slice(0, 200);
}

// 🛡️ 스키마 검증 및 정제 (XSS / JSON 폭탄 / 프로토타입 오염 방지)
function sanitizeSyncPayload(raw, securityConfig) {
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

    // 장소별 할 일(localTodos) 배열 정제 (최대 50개)
    const rawLocalTodos = Array.isArray(p.localTodos) ? p.localTodos.slice(0, 50) : [];
    const localTodos = rawLocalTodos
      .filter((t) => t && typeof t === "object")
      .map((t, idx) => ({
        id: cleanString(String(t.id || `lt-${idx}`), 64, `lt-${idx}`).replace(
          /[^a-zA-Z0-9_-]/g,
          ""
        ),
        text: cleanString(t.text, 120, "할 일"),
        done: Boolean(t.done),
      }));

    pins.push({
      id: cleanString(String(p.id || `pin-${Date.now()}`), 64, `pin-${Date.now()}`).replace(
        /[^a-zA-Z0-9_-]/g,
        ""
      ),
      // Day 구분 및 장소별 할 일 보존 (서버가 필드를 버리지 않고 동기화하도록 보장)
      dayId: cleanString(String(p.dayId || "day-1"), 32, "day-1").replace(
        /[^a-zA-Z0-9_-]/g,
        ""
      ),
      dayLabel: cleanString(p.dayLabel, 40, "Day 1"),
      localTodos,
      name: typeof p.name === "string" ? cleanString(p.name, 120, "") : cleanString(p.name, 120, "여행 장소"),
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
      content: cleanMultilineString(n.content, 30000, ""),
      updatedAt: cleanString(n.updatedAt, 60, new Date().toLocaleString("ko-KR")),
      updatedAtMs: clampNumber(
        n.updatedAtMs || Date.parse(n.updatedAt) || 0,
        0,
        Date.now() + 60000,
        Date.now()
      ),
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

  const rawDays = Array.isArray(raw.days) ? raw.days.slice(0, 50) : [];
  const days = rawDays
    .filter((d) => d && typeof d === "object")
    .map((d, idx) => ({
      id: cleanString(String(d.id || `day-${idx + 1}`), 32, `day-${idx + 1}`).replace(
        /[^a-zA-Z0-9_-]/g,
        ""
      ),
      label: cleanString(d.label, 40, `Day ${idx + 1}`),
    }));

  return {
    pins,
    days: days.length > 0 ? days : [{ id: "day-1", label: "Day 1" }],
    tripTitle: cleanString(raw.tripTitle, 80, "우리의 여행 ✈️"),
    exchangeRate: clampNumber(raw.exchangeRate, 0.5, 100, 9.05),
    peopleCount: Math.round(clampNumber(raw.peopleCount, 1, 50, 2)),
    notes,
    checklist,
    explicitlyCleared: Boolean(raw.explicitlyCleared),
    forceOverwrite: Boolean(raw.forceOverwrite),
    updatedAt: clampNumber(raw.updatedAt, 0, Date.now() + 60000, Date.now()),
    clientId: cleanString(raw.clientId, 64, "unknown").replace(/[^a-zA-Z0-9_-]/g, ""),
    securityConfig,
  };
}

function stripSensitiveFieldsForClient(data) {
  if (!data || typeof data !== "object") {
    return {
      pins: [],
      days: [{ id: "day-1", label: "Day 1" }],
      notes: [],
      checklist: [],
      empty: true,
      updatedAt: 0,
    };
  }
  const { lockHash, securityConfig, ...safeData } = data;
  return {
    days: Array.isArray(safeData.days) && safeData.days.length > 0 ? safeData.days : [{ id: "day-1", label: "Day 1" }],
    ...safeData,
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

async function persistSecurityConfigOnly(existingData, securityConfig) {
  const payload =
    existingData && typeof existingData === "object"
      ? { ...existingData, securityConfig }
      : {
          pins: [],
          tripTitle: "우리의 여행 ✈️",
          exchangeRate: 9.05,
          peopleCount: 2,
          notes: [],
          checklist: [],
          updatedAt: Date.now(),
          securityConfig,
        };
  memoryFallback = payload;
  try {
    await saveToSupabase(payload);
  } catch {
    // 메모리 캐시에 이미 유지됨
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

  // 🔒 환경변수 검증 (키 노출 없이 명확한 500 에러 반환)
  if (!SUPABASE_URL || !SUPABASE_ANON_KEY) {
    return res.status(500).json({
      ok: false,
      error: "Server configuration missing: SUPABASE_URL / SUPABASE_ANON_KEY",
    });
  }

  const clientIp = getClientIp(req);
  if (!checkRateLimit(clientIp, req.method)) {
    return res.status(429).json({
      ok: false,
      error: "요청이 너무 많습니다. 잠시 후 다시 시도해주세요.",
    });
  }

  try {
    // 현재 클라우드 데이터 및 보안 설정 로드
    let existing = null;
    try {
      existing = await fetchFromSupabase();
      if (existing) memoryFallback = existing;
    } catch {
      existing = memoryFallback;
    }

    const securityConfig = ensureSecurityConfig(existing);
    const ipStatus = getIpStatus(clientIp, securityConfig);

    // =========================================================================
    // 1. GET 요청: 유효한 접속 비밀번호 헤더(X-Planner-Pin)가 있어야만 데이터 반환
    // =========================================================================
    if (req.method === "GET") {
      if (ipStatus.banned) {
        return res.status(403).json({
          ok: false,
          ipBanned: true,
          clientIp,
          error: `🚫 비밀번호 ${MAX_PIN_FAILS}회 연속 오류로 인해 현재 IP(${clientIp})의 접속이 자동 차단되었습니다.`,
        });
      }

      const headerPin = cleanString(req.headers["x-planner-pin"] || "", 64, "");
      if (!headerPin || !verifyAccessPassword(headerPin, securityConfig)) {
        return res.status(401).json({
          ok: false,
          requiresAuth: true,
          clientIp,
          remainingAttempts: Math.max(0, MAX_PIN_FAILS - ipStatus.fails),
          error: "시작 페이지 비밀번호 인증이 필요합니다.",
        });
      }

      return res.status(200).json(stripSensitiveFieldsForClient(existing || memoryFallback));
    }

    // =========================================================================
    // 2. POST 요청: 인증 / 관리자 설정 / 데이터 동기화
    // =========================================================================
    if (req.method === "POST") {
      // CSRF 방어: 전용 커스텀 헤더 확인
      const requestedWith = req.headers["x-requested-with"];
      if (requestedWith !== "SmartTravelPlanner-v2") {
        return res.status(403).json({
          ok: false,
          error: "승인되지 않은 외부 요청입니다 (CSRF Blocked).",
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
        return res.status(400).json({ ok: false, error: "잘못된 JSON 형식입니다." });
      }

      const action = cleanString(body.action || "", 40, "");

      // -----------------------------------------------------------------------
      // 👑 관리자 전용 액션들 (PBKDF2-SHA512 마스터 해시 검증)
      // -----------------------------------------------------------------------
      if (
        action === "adminLogin" ||
        action === "adminSetPrimaryPassword" ||
        action === "adminAddPassword" ||
        action === "adminDeletePassword" ||
        action === "adminUnbanIp"
      ) {
        // 관리자 키조차 무차별 대입하는 공격 차단 (8회 이상 실패 시 관리자 인증도 완전 차단)
        if (ipStatus.fails >= MAX_PIN_FAILS + 3) {
          return res.status(403).json({
            ok: false,
            ipBanned: true,
            clientIp,
            error: `🚫 반복된 인증 실패로 현재 IP(${clientIp})에서의 모든 접근이 차단되었습니다.`,
          });
        }

        const candidateAdminKey = cleanString(body.adminKey || "", 64, "");
        if (!verifyAdminMasterKey(candidateAdminKey)) {
          const updatedIp = registerIpFailure(clientIp, securityConfig);
          await persistSecurityConfigOnly(existing, securityConfig);

          if (updatedIp.banned) {
            return res.status(403).json({
              ok: false,
              ipBanned: true,
              clientIp,
              remainingAttempts: 0,
              error: `🚫 비밀번호 ${MAX_PIN_FAILS}회 오류로 현재 IP(${clientIp})가 자동 차단되었습니다.`,
            });
          }

          return res.status(401).json({
            ok: false,
            remainingAttempts: Math.max(0, MAX_PIN_FAILS - updatedIp.fails),
            error: `관리자 비밀번호가 일치하지 않습니다. (남은 기회: ${Math.max(
              0,
              MAX_PIN_FAILS - updatedIp.fails
            )}회 / ${MAX_PIN_FAILS}회 실패 시 IP 차단)`,
          });
        }

        // 관리자 인증 성공 → 본인 IP의 실패 기록/차단 즉시 해제
        resetIpFailure(clientIp, securityConfig);

        if (action === "adminLogin") {
          await persistSecurityConfigOnly(existing, securityConfig);
          return res.status(200).json({
            ok: true,
            adminAuthorized: true,
            ...formatAdminClientPayload(securityConfig),
          });
        }

        if (action === "adminSetPrimaryPassword" || action === "adminAddPassword") {
          const newPassword = cleanString(body.newPassword || "", 64, "");
          const label = cleanString(
            body.label ||
              (action === "adminSetPrimaryPassword" ? "관리자 지정 비밀번호" : "추가 허용 비밀번호"),
            40,
            "지정 비밀번호"
          );

          if (newPassword.length < 4) {
            return res.status(400).json({
              ok: false,
              error: "지정할 비밀번호는 최소 4자 이상이어야 합니다.",
            });
          }

          const newSalt = `JP635_CUSTOM_${crypto.randomBytes(16).toString("hex")}`;
          const newHash = derivePbkdf2Hex(newPassword, newSalt);
          const newEntry = {
            id: `pw-${Date.now()}-${crypto.randomBytes(3).toString("hex")}`,
            label,
            maskedHint: maskPasswordHint(newPassword),
            salt: newSalt,
            hash: newHash,
            createdAt: new Date().toLocaleString("ko-KR"),
          };

          if (action === "adminSetPrimaryPassword") {
            // 오직 이 비밀번호만 유효하도록 단독 지정
            securityConfig.accessEntries = [newEntry];
          } else {
            // 기존 비밀번호 유지 + 새 비밀번호 추가 (최대 10개)
            securityConfig.accessEntries = [
              ...(securityConfig.accessEntries || []).slice(0, 9),
              newEntry,
            ];
          }

          await persistSecurityConfigOnly(existing, securityConfig);
          return res.status(200).json({
            ok: true,
            message:
              action === "adminSetPrimaryPassword"
                ? "✅ 접속 비밀번호가 새 비밀번호로 단독 변경되었습니다."
                : "✅ 새 접속 허용 비밀번호가 추가 등록되었습니다.",
            ...formatAdminClientPayload(securityConfig),
          });
        }

        if (action === "adminDeletePassword") {
          const entryId = cleanString(body.entryId || "", 64, "");
          const currentList = securityConfig.accessEntries || [];
          if (currentList.length <= 1) {
            return res.status(400).json({
              ok: false,
              error: "최소 1개의 접속 비밀번호는 유지되어야 합니다. 새 비밀번호를 먼저 추가하거나 변경해주세요.",
            });
          }
          securityConfig.accessEntries = currentList.filter((e) => e.id !== entryId);
          await persistSecurityConfigOnly(existing, securityConfig);
          return res.status(200).json({
            ok: true,
            message: "🗑️ 선택한 비밀번호가 삭제되었습니다.",
            ...formatAdminClientPayload(securityConfig),
          });
        }

        if (action === "adminUnbanIp") {
          const targetIp = cleanString(body.targetIp || "", 64, "");
          if (targetIp === "ALL") {
            securityConfig.ipRecords = {};
            ipSecurityMemory.clear();
          } else if (targetIp) {
            resetIpFailure(targetIp, securityConfig);
          }
          await persistSecurityConfigOnly(existing, securityConfig);
          return res.status(200).json({
            ok: true,
            message: "🔓 IP 차단이 해제되었습니다.",
            ...formatAdminClientPayload(securityConfig),
          });
        }
      }

      // -----------------------------------------------------------------------
      // 🚫 일반 요청 시 IP 차단 여부 우선 확인 (5회 실패 IP는 즉시 403 차단)
      // -----------------------------------------------------------------------
      if (ipStatus.banned) {
        return res.status(403).json({
          ok: false,
          ipBanned: true,
          clientIp,
          remainingAttempts: 0,
          error: `🚫 비밀번호 ${MAX_PIN_FAILS}회 연속 오류로 인해 현재 IP(${clientIp})의 접속이 자동 차단되었습니다.`,
        });
      }

      const providedPin = cleanString(
        req.headers["x-planner-pin"] || body.password || body.authPin || "",
        64,
        ""
      );

      // -----------------------------------------------------------------------
      // 🎲 1) 동적 난수 초대 티켓 생성 요청 (action === "generateInviteTicket")
      //    - 비밀번호를 외부에 노출하지 않고 매번 새로운 난수 토큰 링크 생성
      // -----------------------------------------------------------------------
      if (action === "generateInviteTicket") {
        if (!verifyAccessPassword(providedPin, securityConfig) && !verifyAdminMasterKey(body.adminKey)) {
          return res.status(401).json({ ok: false, error: "인증 권한이 없습니다." });
        }
        const ticket = crypto.randomBytes(24).toString("hex");
        const newTicket = {
          ticket,
          label: cleanString(body.label || "동행인 초대 티켓", 60, "초대 링크"),
          createdAt: Date.now(),
          expiresAt: Date.now() + 14 * 24 * 60 * 60 * 1000, // 14일 유효
        };
        securityConfig.inviteTickets = [
          newTicket,
          ...(securityConfig.inviteTickets || []).filter((t) => (t.expiresAt || 0) > Date.now()).slice(0, 49)
        ];
        await persistSecurityConfigOnly(existing, securityConfig);
        return res.status(200).json({ ok: true, ticket });
      }

      // -----------------------------------------------------------------------
      // 🎫 2) 동적 난수 초대 티켓 수락/인증 요청 (action === "redeemInviteTicket")
      // -----------------------------------------------------------------------
      if (action === "redeemInviteTicket") {
        const ticketCandidate = cleanString(body.ticket || "", 64, "");
        const matched = (securityConfig.inviteTickets || []).find(
          (t) => t.ticket === ticketCandidate && Number(t.expiresAt || 0) > Date.now()
        );
        if (matched) {
          resetIpFailure(clientIp, securityConfig);
          await persistSecurityConfigOnly(existing, securityConfig);
          return res.status(200).json({
            ok: true,
            authenticated: true,
            ticket: ticketCandidate,
            clientIp,
            cloudData: stripSensitiveFieldsForClient(existing),
          });
        }

        const updatedIp = registerIpFailure(clientIp, securityConfig);
        await persistSecurityConfigOnly(existing, securityConfig);
        if (updatedIp.banned) {
          return res.status(403).json({
            ok: false,
            ipBanned: true,
            clientIp,
            remainingAttempts: 0,
            error: `🚫 초대 링크 오류 ${MAX_PIN_FAILS}회로 현재 IP(${clientIp})가 자동 차단되었습니다.`,
          });
        }
        return res.status(401).json({
          ok: false,
          error: "유효하지 않거나 만료된 초대 링크입니다.",
          remainingAttempts: Math.max(0, MAX_PIN_FAILS - updatedIp.fails),
        });
      }

      // -----------------------------------------------------------------------
      // 🔑 3) 시작 페이지 입장 비밀번호 검증 요청 (action === "authenticateEntry")
      // -----------------------------------------------------------------------
      if (action === "authenticateEntry") {
        // 만약 시작 페이지 입력칸에 관리자 전용 마스터 키를 바로 입력한 경우 → 관리자 페이지 즉시 오픈 + 입장 허용!
        if (verifyAdminMasterKey(providedPin)) {
          resetIpFailure(clientIp, securityConfig);
          await persistSecurityConfigOnly(existing, securityConfig);
          return res.status(200).json({
            ok: true,
            authenticated: true,
            openedAdmin: true,
            clientIp,
            cloudData: stripSensitiveFieldsForClient(existing),
            ...formatAdminClientPayload(securityConfig),
          });
        }

        if (verifyAccessPassword(providedPin, securityConfig)) {
          resetIpFailure(clientIp, securityConfig);
          await persistSecurityConfigOnly(existing, securityConfig);
          return res.status(200).json({
            ok: true,
            authenticated: true,
            openedAdmin: false,
            clientIp,
            cloudData: stripSensitiveFieldsForClient(existing),
          });
        }

        // 비밀번호 불일치 → 실패 횟수 증가 및 5회 도달 시 IP 즉시 차단
        const updatedIp = registerIpFailure(clientIp, securityConfig);
        await persistSecurityConfigOnly(existing, securityConfig);

        if (updatedIp.banned) {
          return res.status(403).json({
            ok: false,
            ipBanned: true,
            clientIp,
            remainingAttempts: 0,
            error: `🚫 비밀번호 ${MAX_PIN_FAILS}회 연속 오류로 인해 현재 IP(${clientIp})의 접속이 자동 차단되었습니다.`,
          });
        }

        const remaining = Math.max(0, MAX_PIN_FAILS - updatedIp.fails);
        return res.status(401).json({
          ok: false,
          ipBanned: false,
          clientIp,
          remainingAttempts: remaining,
          error: `비밀번호가 일치하지 않습니다. (남은 기회: ${remaining}회 / ${MAX_PIN_FAILS}회 실패 시 IP 자동 차단)`,
        });
      }

      // -----------------------------------------------------------------------
      // ☁️ 일반 일정·메모 저장 요청: 반드시 유효한 접속 비밀번호 헤더가 있어야만 허용
      // -----------------------------------------------------------------------
      if (!providedPin || !verifyAccessPassword(providedPin, securityConfig)) {
        const updatedIp = registerIpFailure(clientIp, securityConfig);
        await persistSecurityConfigOnly(existing, securityConfig);
        return res.status(401).json({
          ok: false,
          requiresAuth: true,
          ipBanned: updatedIp.banned,
          remainingAttempts: Math.max(0, MAX_PIN_FAILS - updatedIp.fails),
          error: "🔒 인증이 만료되었거나 비밀번호가 변경되었습니다. 다시 로그인해주세요.",
        });
      }

      // 🛡️ [수정 B] 빈 초기 기기가 기존 클라우드 데이터를 덮어쓰는 현상 방지 & 스마트 데이터 보존
      const incomingPins = Array.isArray(body.pins) ? body.pins : [];
      const incomingDays = Array.isArray(body.days) ? body.days : [];
      const incomingNotes = Array.isArray(body.notes) ? body.notes : [];
      const incomingChecklist = Array.isArray(body.checklist) ? body.checklist : [];

      const existingPins = existing && Array.isArray(existing.pins) ? existing.pins : [];
      const existingDays = existing && Array.isArray(existing.days) ? existing.days : [];
      const existingNotes = existing && Array.isArray(existing.notes) ? existing.notes : [];
      const existingChecklist = existing && Array.isArray(existing.checklist) ? existing.checklist : [];

      const isExplicitReset = Boolean(body.explicitlyCleared);
      const isForceOverwrite = Boolean(body.forceOverwrite);

      if (!isExplicitReset && !isForceOverwrite) {
        // 1) 핀(pins) 방어: 들어오는 핀이 비어 있고 기존에 핀이 있으면 기존 핀 유지
        if (incomingPins.length === 0 && existingPins.length > 0) {
          body.pins = existingPins;
        }

        // 2) 일차(days) 방어: 들어오는 days가 비어 있고 기존에 days가 있으면 기존 days 유지
        if (incomingDays.length === 0 && existingDays.length > 0) {
          body.days = existingDays;
        }

        // 3) 메모(notes) 방어: 들어오는 notes 내용이 전부 비어 있고 기존에 의미 있는 메모가 있으면 기존 메모 유지 또는 병합
        const incomingHasNotes = hasMeaningfulNotes(incomingNotes);
        const existingHasNotes = hasMeaningfulNotes(existingNotes);

        if (!incomingHasNotes && existingHasNotes) {
          body.notes = existingNotes;
        } else if (incomingHasNotes && existingHasNotes) {
          body.notes = mergeNotes(existingNotes, incomingNotes);
        }

        // 4) 체크리스트(checklist) 방어: 들어오는 checklist가 비어 있고 기존에 항목이 있으면 기존 항목 유지 또는 병합
        const incomingHasCheck = hasMeaningfulChecklist(incomingChecklist);
        const existingHasCheck = hasMeaningfulChecklist(existingChecklist);

        if (!incomingHasCheck && existingHasCheck) {
          body.checklist = existingChecklist;
        } else if (incomingHasCheck && existingHasCheck) {
          body.checklist = mergeChecklist(existingChecklist, incomingChecklist);
        }
      }

      const sanitizedPayload = sanitizeSyncPayload(body, securityConfig);

      memoryFallback = sanitizedPayload;
      await saveToSupabase(sanitizedPayload);

      return res.status(200).json({
        ok: true,
        updatedAt: sanitizedPayload.updatedAt,
        storage: "supabase-couple-calendar-secured-v3",
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
