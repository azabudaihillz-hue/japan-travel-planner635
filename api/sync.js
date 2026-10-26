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

// NOTE: Vercel Environment Variables 설정 (다중 환경변수 키 이름 및 _ 변형 키 폴백 + JWT ref 기반 URL 자동 복원 지원)
function cleanEnvToken(val) {
  if (typeof val !== "string") return "";
  return val
    .trim()
    .replace(/^["'`]+|["'`]+$/g, "")
    .replace(/[\r\n\t]+/g, "")
    .trim();
}

function parseSupabaseAnonJwt(rawToken) {
  const token = cleanEnvToken(rawToken).replace(/\s+/g, "");
  if (!token.startsWith("eyJ")) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const jsonStr = Buffer.from(parts[1], "base64url").toString("utf8");
    const payload = JSON.parse(jsonStr);
    if (!payload || typeof payload !== "object") return null;
    if (payload.role === "service_role") return null;
    if (payload.iss === "supabase" || typeof payload.ref === "string") {
      return {
        token,
        ref: typeof payload.ref === "string" ? payload.ref.trim() : "",
        role: payload.role || "anon",
      };
    }
  } catch {}
  return null;
}

function normalizeSupabaseBaseUrl(rawUrl) {
  const cleaned = cleanEnvToken(rawUrl).replace(/\s+/g, "");
  if (!cleaned) return "";

  const dashMatch = cleaned.match(/supabase\.com\/dashboard\/project\/([a-z0-9-]+)/i);
  if (dashMatch && dashMatch[1]) {
    return `https://${dashMatch[1].toLowerCase()}.supabase.co`;
  }

  const hostMatch = cleaned.match(/([a-z0-9-]{12,40})\.supabase\.co/i);
  if (hostMatch && hostMatch[1]) {
    return `https://${hostMatch[1].toLowerCase()}.supabase.co`;
  }

  if (/^https?:\/\//i.test(cleaned)) {
    return cleaned.replace(/\/rest\/v1.*$/i, "").replace(/\/+$/, "");
  }
  return "";
}

let cachedWorkingCreds = null;

function resolveSupabaseCredentialsList() {
  const env = process.env || {};
  const urlPriorityKeys = [
    "EXPO_PUBLIC_COUPLE_SUPABASE_URL",
    "EXPO_PUBLIC_COUPLE_SUPABASE_URL_",
    "EXPO_PUBLIC__COUPLE_SUPABASE_URL",
    "SUPABASE_URL_",
    "SUPABASE__URL",
    "_SUPABASE_URL",
    "EXPO_PUBLIC_SUPABASE_URL_",
    "EXPO_PUBLIC__SUPABASE_URL",
    "SUPABASE_URL",
    "EXPO_PUBLIC_SUPABASE_URL",
    "NEXT_PUBLIC_SUPABASE_URL",
    "VITE_SUPABASE_URL",
  ];

  const keyPriorityKeys = [
    "EXPO_PUBLIC_COUPLE_SUPABASE_ANON_KEY",
    "EXPO_PUBLIC_COUPLE_SUPABASE_ANON_KEY_",
    "EXPO_PUBLIC__COUPLE_SUPABASE_ANON_KEY",
    "SUPABASE_ANON_KEY_",
    "SUPABASE__ANON_KEY",
    "_SUPABASE_ANON_KEY",
    "EXPO_PUBLIC_SUPABASE_ANON_KEY_",
    "EXPO_PUBLIC__SUPABASE_ANON_KEY",
    "SUPABASE_ANON_KEY",
    "EXPO_PUBLIC_SUPABASE_ANON_KEY",
    "NEXT_PUBLIC_SUPABASE_ANON_KEY",
    "VITE_SUPABASE_ANON_KEY",
  ];

  const urlSet = new Set();
  const keyList = [];
  const keySeen = new Set();

  const addKeyCandidate = (rawVal) => {
    const cleaned = cleanEnvToken(rawVal).replace(/\s+/g, "");
    if (!cleaned || cleaned.length < 20 || keySeen.has(cleaned)) return;
    if (/^https?:\/\//i.test(cleaned)) return;
    const jwtInfo = parseSupabaseAnonJwt(cleaned);
    keySeen.add(cleaned);
    keyList.push({
      key: jwtInfo ? jwtInfo.token : cleaned,
      refUrl:
        jwtInfo && jwtInfo.ref ? `https://${jwtInfo.ref.toLowerCase()}.supabase.co` : "",
      isVerifiedJwt: Boolean(jwtInfo),
    });
    if (jwtInfo && jwtInfo.ref) {
      urlSet.add(`https://${jwtInfo.ref.toLowerCase()}.supabase.co`);
    }
  };

  const addUrlCandidate = (rawVal) => {
    const norm = normalizeSupabaseBaseUrl(rawVal);
    if (norm && !norm.includes("your-project")) {
      urlSet.add(norm);
    }
  };

  for (const k of keyPriorityKeys) {
    if (env[k]) addKeyCandidate(env[k]);
  }
  for (const k of urlPriorityKeys) {
    if (env[k]) addUrlCandidate(env[k]);
  }

  // 전체 process.env 스캔: 변수명에 _가 추가되었거나 URL/키가 다른 이름으로 저장된 경우까지 자동 탐지
  for (const [envName, envVal] of Object.entries(env)) {
    if (!envVal || typeof envVal !== "string") continue;
    if (/SERVICE_ROLE/i.test(envName)) continue;
    if (/SUPABASE/i.test(envName) || envVal.includes(".supabase.co") || envVal.startsWith("eyJ")) {
      addKeyCandidate(envVal);
      addUrlCandidate(envVal);
    }
  }

  // 검증된 JWT 키를 최우선 정렬
  keyList.sort((a, b) => Number(b.isVerifiedJwt) - Number(a.isVerifiedJwt));

  const pairs = [];
  const pairSeen = new Set();

  const pushPair = (url, key) => {
    if (!url || !key) return;
    const sig = `${url}|${key}`;
    if (pairSeen.has(sig)) return;
    pairSeen.add(sig);
    pairs.push({ url, key });
  };

  if (cachedWorkingCreds && cachedWorkingCreds.url && cachedWorkingCreds.key) {
    pushPair(cachedWorkingCreds.url, cachedWorkingCreds.key);
  }

  // 1순위: JWT 내부 ref와 정확히 일치하는 URL + Key 조합
  for (const kObj of keyList) {
    if (kObj.refUrl) {
      pushPair(kObj.refUrl, kObj.key);
    }
  }

  // 2순위: 수집된 모든 유효 URL + Key 조합
  for (const kObj of keyList) {
    for (const u of urlSet) {
      pushPair(u, kObj.key);
    }
  }

  return pairs;
}

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

// 초대 티켓 자체 서명 검증용 파생 시크릿 (서버리스 콜드스타트·동기화 지연 시에도 유효한 초대코드가 만료로 오판되지 않도록 보장)
const INVITE_HMAC_SECRET = `JP635_INVITE_SIGN_v4_${ADMIN_MASTER_SALT}_${DEFAULT_ENTRY_PBKDF2_HASH.slice(0, 32)}`;

const MAX_PIN_FAILS = 5;
// ⏱️ IP 잠금 자동 해제 시간: 10분 (영구 차단 대신 10분 후 자동 해제 + 카운트다운 제공)
const BAN_DURATION_MS = 10 * 60 * 1000;

let memoryFallback = null;
let securityConfigMemory = null;

// 🛡️ IP별 요청 속도 제한 (Rate Limiter) 및 오입력/차단 메모리 캐시
const rateLimitStore = new Map();
const ipSecurityMemory = new Map();

function safeDecodeHeaderPin(rawHeader) {
  if (typeof rawHeader !== "string" || !rawHeader) return "";
  const trimmed = rawHeader.trim();
  if (!trimmed) return "";
  try {
    return decodeURIComponent(trimmed);
  } catch {
    return trimmed;
  }
}

function normalizeInviteCode(raw) {
  if (typeof raw !== "string") return "";
  return raw
    .trim()
    .toUpperCase()
    .replace(/[\s_-]+/g, "");
}

function formatReadableInviteCode(normCode) {
  const clean = normalizeInviteCode(normCode);
  if (!clean) return "";
  if (clean.startsWith("JP") && clean.length > 2) {
    return `JP-${clean.slice(2)}`;
  }
  return clean;
}

function generateRandomShortCode(existingTickets = []) {
  const alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
  const existingSet = new Set(
    (existingTickets || []).map((t) => normalizeInviteCode(t.code || ""))
  );
  for (let attempt = 0; attempt < 20; attempt++) {
    let part = "";
    const bytes = crypto.randomBytes(4);
    for (let i = 0; i < 4; i++) {
      part += alphabet[bytes[i] % alphabet.length];
    }
    const candidate = `JP-${part}`;
    if (!existingSet.has(normalizeInviteCode(candidate))) {
      return candidate;
    }
  }
  return `JP-${crypto.randomBytes(3).toString("hex").toUpperCase()}`;
}

function createSignedInviteTicket({ id, code, label, createdAt }) {
  const cleanId = String(id || `inv-${Date.now()}`).replace(/[^a-zA-Z0-9_-]/g, "");
  const codeNorm = normalizeInviteCode(code || "JP0000");
  const ts = Number(createdAt) || Date.now();
  const labelB64 = Buffer.from(String(label || "동행인 초대"), "utf8").toString("base64url");
  const sig = crypto
    .createHmac("sha256", INVITE_HMAC_SECRET)
    .update(`${cleanId}:${codeNorm}:${ts}:${labelB64}`)
    .digest("hex")
    .slice(0, 24);
  return `inv2.${cleanId}.${codeNorm}.${ts}.${sig}.${labelB64}`;
}

function verifyAndParseSignedTicket(rawTicket) {
  if (typeof rawTicket !== "string") return null;
  const trimmed = rawTicket.trim();
  if (trimmed.startsWith("inv2.")) {
    const parts = trimmed.split(".");
    if (parts.length >= 6) {
      const [, cleanId, codeNorm, tsStr, sig, ...labelParts] = parts;
      const labelB64 = labelParts.join(".");
      const ts = Number(tsStr);
      if (!cleanId || !codeNorm || !Number.isFinite(ts) || !sig) return null;
      const expectedSig = crypto
        .createHmac("sha256", INVITE_HMAC_SECRET)
        .update(`${cleanId}:${codeNorm}:${ts}:${labelB64}`)
        .digest("hex")
        .slice(0, 24);
      if (!safeTimingEqualHex(sig, expectedSig)) return null;
      let label = "동행인 초대 코드";
      try {
        label = Buffer.from(labelB64, "base64url").toString("utf8") || "동행인 초대 코드";
      } catch {}
      return {
        id: cleanId,
        code: formatReadableInviteCode(codeNorm),
        ticket: trimmed,
        label: cleanString(label, 60, "동행인 초대 코드"),
        createdAt: ts,
      };
    }
    return null;
  }
  // 이전 버전 호환: 48자리 hex 난수 티켓도 만료 오판 없이 자동 복구 허용
  if (/^[a-f0-9]{32,64}$/i.test(trimmed)) {
    const suffix = trimmed.slice(0, 4).toUpperCase();
    return {
      id: `inv-legacy-${trimmed.slice(0, 10).toLowerCase()}`,
      code: `JP-${suffix}`,
      ticket: trimmed,
      label: "기존 발송 초대 링크",
      createdAt: Date.now(),
      isLegacyHex: true,
    };
  }
  return null;
}

function extractInviteTokenFromInput(rawInput) {
  if (typeof rawInput !== "string") return "";
  const trimmed = rawInput.trim();
  if (!trimmed) return "";
  const clean = trimmed.startsWith("ticket:") ? trimmed.slice(7).trim() : trimmed;

  // URL 전체를 복사해서 붙여넣은 경우 (?invite=... 또는 #invite=...)
  if (clean.includes("invite=") || clean.includes("ticket=")) {
    const match = clean.match(/[?#&](?:invite|ticket)=([^&#\s]+)/i);
    if (match && match[1]) {
      try {
        return decodeURIComponent(match[1].trim());
      } catch {
        return match[1].trim();
      }
    }
  }
  return clean;
}

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
  const maxReq = method === "POST" ? 60 : 120;

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

function normalizeInviteItem(rawItem, idx = 0) {
  if (!rawItem || typeof rawItem !== "object") return null;
  const createdAt = Number(rawItem.createdAt) || Date.now();
  const rawTicketStr = typeof rawItem.ticket === "string" ? rawItem.ticket.trim() : "";
  const defaultId =
    !rawItem.id && /^[a-f0-9]{32,64}$/i.test(rawTicketStr)
      ? `inv-legacy-${rawTicketStr.slice(0, 10).toLowerCase()}`
      : `inv-${createdAt}-${idx}`;
  const id = cleanString(String(rawItem.id || defaultId), 64, defaultId).replace(
    /[^a-zA-Z0-9_-]/g,
    ""
  );
  const label = cleanString(
    rawItem.label || `동행인 초대 #${idx + 1}`,
    60,
    `동행인 초대 #${idx + 1}`
  );
  const rawCode = cleanString(rawItem.code || "", 32, "");
  const code = rawCode
    ? formatReadableInviteCode(rawCode)
    : `JP-${String(rawTicketStr || id).slice(0, 4).toUpperCase()}`;
  const ticket =
    rawTicketStr.length >= 16
      ? rawTicketStr
      : createSignedInviteTicket({ id, code, label, createdAt });

  return {
    id,
    code,
    ticket,
    label,
    active: rawItem.active !== false,
    createdAt,
    createdAtText:
      cleanString(rawItem.createdAtText || "", 60, "") ||
      new Date(createdAt).toLocaleString("ko-KR"),
    expiresAt: Number(rawItem.expiresAt) || createdAt + 10 * 365 * 24 * 60 * 60 * 1000,
    useCount: Math.max(0, Math.round(Number(rawItem.useCount) || 0)),
    lastUsedAt: rawItem.lastUsedAt ? cleanString(String(rawItem.lastUsedAt), 60, "") : null,
    updatedAt: Number(rawItem.updatedAt) || createdAt,
  };
}

function ensureSecurityConfig(existingObj) {
  const cloudBase =
    existingObj &&
    typeof existingObj === "object" &&
    existingObj.securityConfig &&
    typeof existingObj.securityConfig === "object"
      ? existingObj.securityConfig
      : {};

  const memBase =
    securityConfigMemory && typeof securityConfigMemory === "object"
      ? securityConfigMemory
      : {};

  // 1) 삭제(영구 폐기)된 초대 코드 ID/티켓 목록 병합
  const revokedSet = new Set(
    [
      ...(Array.isArray(cloudBase.revokedTickets) ? cloudBase.revokedTickets : []),
      ...(Array.isArray(memBase.revokedTickets) ? memBase.revokedTickets : []),
    ].filter((x) => typeof x === "string" && x.length > 0)
  );
  const revokedTickets = Array.from(revokedSet).slice(0, 200);

  // 2) 삭제된 비밀번호 ID 목록 병합 및 접속 허용 비밀번호 병합 (콜드스타트 메모리가 클라우드 커스텀 비밀번호를 덮어쓰지 않도록 보호)
  const deletedPwSet = new Set(
    [
      ...(Array.isArray(cloudBase.deletedPasswordIds) ? cloudBase.deletedPasswordIds : []),
      ...(Array.isArray(memBase.deletedPasswordIds) ? memBase.deletedPasswordIds : []),
    ].filter((x) => typeof x === "string" && x.length > 0)
  );
  const deletedPasswordIds = Array.from(deletedPwSet).slice(0, 200);

  const filterValidEntries = (arr) =>
    Array.isArray(arr)
      ? arr.filter(
          (e) =>
            e &&
            typeof e === "object" &&
            typeof e.salt === "string" &&
            typeof e.hash === "string" &&
            e.hash.length === 128 &&
            !deletedPwSet.has(String(e.id || ""))
        )
      : [];

  const cloudEntries = filterValidEntries(cloudBase.accessEntries);
  const memEntries = filterValidEntries(memBase.accessEntries);

  const entryMap = new Map();
  const primaryReplacedAt = Math.max(
    Number(cloudBase.primaryReplacedAt) || 0,
    Number(memBase.primaryReplacedAt) || 0
  );

  // 클라우드와 메모리의 모든 유효 비밀번호를 ID/해시 기준으로 통합 보존
  const combinedSource =
    (Number(memBase.configUpdatedAt) || 0) > (Number(cloudBase.configUpdatedAt) || 0)
      ? [...memEntries, ...cloudEntries]
      : [...cloudEntries, ...memEntries];

  for (const entry of combinedSource) {
    const key = String(entry.id || entry.hash);
    if (!entryMap.has(key)) {
      entryMap.set(key, entry);
    }
  }

  let accessEntries = Array.from(entryMap.values()).slice(0, 15);

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

  // 3) IP 기록 병합 및 만료된 차단(10분 경과) 자동 해제
  const now = Date.now();
  const ipRecords =
    cloudBase.ipRecords &&
    typeof cloudBase.ipRecords === "object" &&
    !Array.isArray(cloudBase.ipRecords)
      ? { ...cloudBase.ipRecords }
      : {};

  for (const [ip, memRec] of ipSecurityMemory.entries()) {
    const cloudRec = ipRecords[ip];
    if (
      !cloudRec ||
      (Number(memRec.lastAttemptAt) || 0) >= (Number(cloudRec.lastAttemptAt) || 0)
    ) {
      ipRecords[ip] = { ...memRec };
    }
  }
  for (const [ip, rec] of Object.entries(ipRecords)) {
    if (!rec || typeof rec !== "object") {
      delete ipRecords[ip];
      continue;
    }
    const lastAttempt = Number(rec.lastAttemptAt) || 0;
    if (lastAttempt > 0 && now - lastAttempt >= BAN_DURATION_MS) {
      delete ipRecords[ip];
      ipSecurityMemory.delete(ip);
    } else {
      ipSecurityMemory.set(ip, { ...rec });
    }
  }

  // 4) 초대 코드 목록 병합 (티켓·ID·단축코드 중복 방지 + 활성/비활성 상태 최신값 반영)
  const inviteMap = new Map();
  const ticketToKey = new Map();
  const rawCloudInvites = Array.isArray(cloudBase.inviteTickets) ? cloudBase.inviteTickets : [];
  const rawMemInvites = Array.isArray(memBase.inviteTickets) ? memBase.inviteTickets : [];

  for (const item of [...rawCloudInvites, ...rawMemInvites]) {
    const norm = normalizeInviteItem(item, inviteMap.size);
    if (!norm) continue;
    const codeNorm = normalizeInviteCode(norm.code);
    if (
      revokedSet.has(norm.id) ||
      revokedSet.has(norm.ticket) ||
      (codeNorm && revokedSet.has(codeNorm))
    ) {
      continue;
    }
    const existingKeyByTicket = norm.ticket ? ticketToKey.get(norm.ticket) : null;
    const key = existingKeyByTicket || norm.id || norm.ticket;
    if (norm.ticket) ticketToKey.set(norm.ticket, key);

    const prev = inviteMap.get(key);
    if (!prev || (Number(norm.updatedAt) || 0) >= (Number(prev.updatedAt) || 0)) {
      inviteMap.set(key, {
        ...norm,
        id: prev?.id || norm.id,
        useCount: Math.max(Number(prev?.useCount) || 0, Number(norm.useCount) || 0),
        lastUsedAt: norm.lastUsedAt || prev?.lastUsedAt || null,
      });
    }
  }

  const inviteTickets = Array.from(inviteMap.values())
    .sort((a, b) => (Number(b.createdAt) || 0) - (Number(a.createdAt) || 0))
    .slice(0, 100);

  const mergedConfig = {
    accessEntries,
    deletedPasswordIds,
    primaryReplacedAt,
    ipRecords,
    inviteTickets,
    revokedTickets,
    configUpdatedAt: Math.max(
      Number(cloudBase.configUpdatedAt) || 0,
      Number(memBase.configUpdatedAt) || 0
    ),
  };

  securityConfigMemory = mergedConfig;
  return mergedConfig;
}

/**
 * 초대 코드 또는 초대 티켓을 찾아 상태를 반환합니다.
 * @returns {{ status: 'active' | 'disabled' | 'revoked' | 'not_found', matched?: object }}
 */
function findInviteStatus(rawInput, securityConfig) {
  if (typeof rawInput !== "string" || !rawInput.trim()) {
    return { status: "not_found" };
  }
  const extracted = extractInviteTokenFromInput(rawInput);
  const codeNorm = normalizeInviteCode(extracted);
  const codeWithPrefix = codeNorm.startsWith("JP") ? codeNorm : `JP${codeNorm}`;
  const revokedSet = new Set(securityConfig?.revokedTickets || []);

  if (
    revokedSet.has(extracted) ||
    (codeNorm && revokedSet.has(codeNorm)) ||
    (codeNorm && revokedSet.has(codeWithPrefix))
  ) {
    return { status: "revoked" };
  }

  const list = Array.isArray(securityConfig?.inviteTickets)
    ? securityConfig.inviteTickets
    : [];

  // 1) 저장된 초대 코드 리스트에서 티켓 또는 단축 코드(JP-XXXX) 일치 확인
  const matched = list.find((t) => {
    if (!t) return false;
    if (t.ticket === extracted || t.id === extracted) return true;
    const tCodeNorm = normalizeInviteCode(t.code || "");
    if (tCodeNorm && (tCodeNorm === codeNorm || tCodeNorm === codeWithPrefix)) {
      return true;
    }
    return false;
  });

  if (matched) {
    if (matched.active === false) {
      return { status: "disabled", matched };
    }
    return { status: "active", matched };
  }

  // 2) 서명된 티켓(inv2.*) 또는 이전 버전 48자 hex 링크인 경우 자동 복구하여 리스트에 등록
  const parsedSigned = verifyAndParseSignedTicket(extracted);
  if (parsedSigned) {
    if (
      revokedSet.has(parsedSigned.id) ||
      revokedSet.has(parsedSigned.ticket) ||
      revokedSet.has(normalizeInviteCode(parsedSigned.code))
    ) {
      return { status: "revoked" };
    }
    const recovered = normalizeInviteItem(
      {
        ...parsedSigned,
        active: true,
        useCount: 0,
        updatedAt: Date.now(),
      },
      list.length
    );
    if (recovered && Array.isArray(securityConfig?.inviteTickets)) {
      securityConfig.inviteTickets = [recovered, ...securityConfig.inviteTickets];
    }
    return { status: "active", matched: recovered };
  }

  return { status: "not_found" };
}

function recordInviteUsage(matchedInvite, securityConfig) {
  if (!matchedInvite || !securityConfig) return;
  const nowStr = new Date().toLocaleString("ko-KR");
  matchedInvite.useCount = (Number(matchedInvite.useCount) || 0) + 1;
  matchedInvite.lastUsedAt = nowStr;
  matchedInvite.updatedAt = Date.now();
  securityConfig.configUpdatedAt = Date.now();
  securityConfigMemory = securityConfig;
}

function verifyAccessPassword(candidate, securityConfig) {
  if (typeof candidate !== "string") return false;
  const trimmed = safeDecodeHeaderPin(candidate).trim();
  if (!trimmed) return false;

  // 1) 초대 티켓 또는 단축 초대 코드(JP-XXXX) 확인 (비활성화된 코드는 즉시 거부)
  const inviteCheck = findInviteStatus(trimmed, securityConfig);
  if (inviteCheck.status === "disabled" || inviteCheck.status === "revoked") {
    return false;
  }
  if (inviteCheck.status === "active" && inviteCheck.matched) {
    return true;
  }

  // 2) 등록된 접속 허용 비밀번호(PBKDF2) 검증
  const entries = Array.isArray(securityConfig?.accessEntries)
    ? securityConfig.accessEntries
    : [];

  for (const entry of entries) {
    const derived = derivePbkdf2Hex(trimmed, entry.salt);
    if (safeTimingEqualHex(derived, entry.hash)) {
      return true;
    }
  }

  // 3) 기본 초기 비밀번호 폴백 검증 (비번 설정 혼선 시에도 원래 기본 비밀번호로 입장 가능)
  const defaultDerived = derivePbkdf2Hex(trimmed, DEFAULT_ENTRY_SALT);
  if (safeTimingEqualHex(defaultDerived, DEFAULT_ENTRY_PBKDF2_HASH)) {
    return true;
  }

  // 4) 관리자 마스터 비밀번호로도 입장 허용
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

  const now = Date.now();
  const lastAttemptAt = Number(rec.lastAttemptAt) || 0;
  const rawBanned = Boolean(rec.banned) || (Number(rec.fails) || 0) >= MAX_PIN_FAILS;

  // 10분 경과 시 자동 차단 해제
  if (rawBanned && lastAttemptAt > 0 && now - lastAttemptAt >= BAN_DURATION_MS) {
    resetIpFailure(ip, securityConfig);
    return {
      fails: 0,
      banned: false,
      bannedAt: null,
      lastAttemptAt: 0,
      banExpiresAt: 0,
      banRemainingSeconds: 0,
    };
  }

  const banExpiresAt = rawBanned
    ? (lastAttemptAt > 0 ? lastAttemptAt : now) + BAN_DURATION_MS
    : 0;
  const banRemainingSeconds = rawBanned
    ? Math.max(1, Math.ceil((banExpiresAt - now) / 1000))
    : 0;

  return {
    fails: Number(rec.fails) || 0,
    banned: rawBanned,
    bannedAt: rec.bannedAt || null,
    lastAttemptAt,
    banExpiresAt,
    banRemainingSeconds,
  };
}

function registerIpFailure(ip, securityConfig) {
  const current = getIpStatus(ip, securityConfig);
  const now = Date.now();
  const nextFails = current.fails + 1;
  const isNowBanned = nextFails >= MAX_PIN_FAILS;
  const banExpiresAt = isNowBanned ? now + BAN_DURATION_MS : 0;
  const banRemainingSeconds = isNowBanned ? Math.ceil(BAN_DURATION_MS / 1000) : 0;

  const updated = {
    fails: nextFails,
    banned: isNowBanned,
    bannedAt: isNowBanned
      ? current.bannedAt || new Date(now).toLocaleString("ko-KR")
      : null,
    lastAttemptAt: now,
    banExpiresAt,
    banRemainingSeconds,
  };
  if (securityConfig && securityConfig.ipRecords) {
    securityConfig.ipRecords[ip] = updated;
  }
  ipSecurityMemory.set(ip, updated);
  return updated;
}

function resetIpFailure(ip, securityConfig) {
  if (securityConfig?.ipRecords?.[ip]) {
    delete securityConfig.ipRecords[ip];
  }
  ipSecurityMemory.delete(ip);
}

function formatInviteTicketsForClient(securityConfig) {
  const list = Array.isArray(securityConfig?.inviteTickets)
    ? securityConfig.inviteTickets
    : [];
  return list.map((t, idx) => ({
    id: String(t.id || `inv-${idx}`),
    code: String(t.code || `JP-${idx + 1}`),
    ticket: String(t.ticket || ""),
    label: String(t.label || `동행인 초대 #${idx + 1}`),
    active: t.active !== false,
    createdAt: Number(t.createdAt) || Date.now(),
    createdAtText:
      String(t.createdAtText || "") ||
      new Date(Number(t.createdAt) || Date.now()).toLocaleString("ko-KR"),
    useCount: Number(t.useCount) || 0,
    lastUsedAt: t.lastUsedAt || null,
  }));
}

function formatAdminClientPayload(securityConfig) {
  const accessEntries = (securityConfig.accessEntries || []).map((e, idx) => ({
    id: String(e.id || `pw-${idx}`),
    label: String(e.label || `허용 비밀번호 #${idx + 1}`),
    maskedHint: String(e.maskedHint || "••••"),
    createdAt: String(e.createdAt || ""),
  }));

  const now = Date.now();
  const bannedIps = Object.entries(securityConfig.ipRecords || {})
    .filter(([, rec]) => {
      if (!rec) return false;
      const last = Number(rec.lastAttemptAt) || 0;
      if (last > 0 && now - last >= BAN_DURATION_MS) return false;
      return rec.banned || (rec.fails || 0) > 0;
    })
    .map(([ip, rec]) => {
      const last = Number(rec.lastAttemptAt) || now;
      const isBanned = Boolean(rec.banned) || (Number(rec.fails) || 0) >= MAX_PIN_FAILS;
      const remainingSec = isBanned
        ? Math.max(0, Math.ceil((last + BAN_DURATION_MS - now) / 1000))
        : 0;
      return {
        ip,
        fails: Number(rec.fails) || 0,
        banned: isBanned,
        bannedAt: rec.bannedAt || "-",
        banRemainingSeconds: remainingSec,
      };
    });

  const inviteTickets = formatInviteTicketsForClient(securityConfig);

  return { accessEntries, bannedIps, inviteTickets };
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

function getSupabaseHeaders(apiKey, extra = {}) {
  return {
    apikey: apiKey,
    Authorization: `Bearer ${apiKey}`,
    "Content-Type": "application/json",
    ...extra,
  };
}

function tryParseJsonObject(val) {
  if (!val) return null;
  if (typeof val === "object" && !Array.isArray(val)) return val;
  if (typeof val === "string") {
    const trimmed = val.trim();
    if (trimmed.startsWith("{")) {
      try {
        const parsed = JSON.parse(trimmed);
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
          return parsed;
        }
      } catch {}
    }
  }
  return null;
}

function extractBestObjectFromRow(row) {
  if (!row || typeof row !== "object") return null;
  const fromHaeMemo = tryParseJsonObject(row.hae_memo);
  const fromHaeShift = tryParseJsonObject(row.hae_shift);
  const fromMemo = tryParseJsonObject(row.memo);

  const candidates = [fromHaeMemo, fromHaeShift, fromMemo].filter(Boolean);
  if (candidates.length === 0) return null;

  // 가장 최신 updatedAt을 가진 객체를 기준으로 하되, securityConfig(초대코드·비밀번호)는 병합 보존
  candidates.sort((a, b) => (Number(b.updatedAt) || 0) - (Number(a.updatedAt) || 0));
  const best = { ...candidates[0] };

  for (const c of candidates) {
    if (c.securityConfig && typeof c.securityConfig === "object") {
      best.securityConfig = {
        ...(best.securityConfig || {}),
        ...c.securityConfig,
        inviteTickets: [
          ...(Array.isArray(best.securityConfig?.inviteTickets)
            ? best.securityConfig.inviteTickets
            : []),
          ...(Array.isArray(c.securityConfig?.inviteTickets)
            ? c.securityConfig.inviteTickets
            : []),
        ],
        accessEntries: [
          ...(Array.isArray(best.securityConfig?.accessEntries)
            ? best.securityConfig.accessEntries
            : []),
          ...(Array.isArray(c.securityConfig?.accessEntries)
            ? c.securityConfig.accessEntries
            : []),
        ],
      };
    }
  }

  return best;
}

async function fetchFromSupabase() {
  const credPairs = resolveSupabaseCredentialsList();
  if (credPairs.length === 0) {
    throw new Error("No valid Supabase credentials found in environment");
  }

  let lastErr = null;
  for (const cred of credPairs) {
    const endpoint = `${cred.url}/rest/v1/couple_calendar?date=eq.${encodeURIComponent(
      SYNC_ROW_KEY
    )}&select=*`;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4500);

    try {
      const res = await fetch(endpoint, {
        method: "GET",
        headers: getSupabaseHeaders(cred.key, { "Cache-Control": "no-cache" }),
        signal: controller.signal,
      });

      if (!res.ok) {
        lastErr = new Error(`Supabase GET status ${res.status}`);
        continue;
      }

      const rows = await res.json();
      cachedWorkingCreds = cred;

      if (!Array.isArray(rows) || rows.length === 0) {
        return null;
      }

      return extractBestObjectFromRow(rows[0]);
    } catch (err) {
      lastErr = err;
    } finally {
      clearTimeout(timer);
    }
  }

  throw lastErr || new Error("Supabase GET failed across all credential candidates");
}

async function saveToSupabase(payload) {
  const credPairs = resolveSupabaseCredentialsList();
  if (credPairs.length === 0) {
    throw new Error("No valid Supabase credentials found in environment");
  }

  const jsonStr = JSON.stringify(payload);
  let lastErr = null;

  for (const cred of credPairs) {
    const endpoint = `${cred.url}/rest/v1/couple_calendar?on_conflict=date`;

    const attemptUpsert = async (rowBody) => {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 4500);
      try {
        const res = await fetch(endpoint, {
          method: "POST",
          headers: getSupabaseHeaders(cred.key, {
            Prefer: "resolution=merge-duplicates,return=minimal",
          }),
          body: JSON.stringify(rowBody),
          signal: controller.signal,
        });
        return res.ok;
      } finally {
        clearTimeout(timer);
      }
    };

    try {
      // 1차: 기존 호환 형식 (hae_shift + hae_memo 동시 기록)
      const okPrimary = await attemptUpsert({
        date: SYNC_ROW_KEY,
        memo: "",
        hae_shift: payload,
        hae_memo: jsonStr,
      }).catch(() => false);

      if (okPrimary) {
        cachedWorkingCreds = cred;
        return true;
      }

      // 2차 폴백: hae_shift 컬럼이 TEXT 타입인 경우 객체 전달 시 400 에러가 날 수 있으므로 null + JSON 문자열로 안전 저장
      const okFallback = await attemptUpsert({
        date: SYNC_ROW_KEY,
        memo: jsonStr,
        hae_shift: null,
        hae_memo: jsonStr,
      }).catch(() => false);

      if (okFallback) {
        cachedWorkingCreds = cred;
        return true;
      }
    } catch (err) {
      lastErr = err;
    }
  }

  throw lastErr || new Error("Supabase UPSERT failed on both primary and fallback schemas");
}

async function persistSecurityConfigOnly(existingData, securityConfig) {
  securityConfig.configUpdatedAt = Date.now();
  securityConfigMemory = securityConfig;

  const baseObj =
    existingData && typeof existingData === "object"
      ? existingData
      : memoryFallback && typeof memoryFallback === "object"
      ? memoryFallback
      : {
          pins: [],
          days: [{ id: "day-1", label: "Day 1" }],
          tripTitle: "우리의 여행 ✈️",
          exchangeRate: 9.05,
          peopleCount: 2,
          notes: [],
          checklist: [],
        };

  const payload = {
    ...baseObj,
    updatedAt: Math.max(Number(baseObj.updatedAt) || 0, Date.now()),
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
    let supabaseFetchFailed = false;
    try {
      existing = await fetchFromSupabase();
      if (existing) memoryFallback = existing;
    } catch {
      supabaseFetchFailed = true;
      existing = memoryFallback;
    }

    const securityConfig = ensureSecurityConfig(existing);
    const ipStatus = getIpStatus(clientIp, securityConfig);

    // =========================================================================
    // 1. GET 요청: 유효한 접속 비밀번호/초대코드 헤더(X-Planner-Pin)가 있어야만 데이터 반환
    // =========================================================================
    if (req.method === "GET") {
      if (ipStatus.banned) {
        return res.status(403).json({
          ok: false,
          ipBanned: true,
          clientIp,
          banExpiresAt: ipStatus.banExpiresAt,
          banRemainingSeconds: ipStatus.banRemainingSeconds,
          error: `🚫 비밀번호/코드 ${MAX_PIN_FAILS}회 연속 오류로 인해 현재 IP(${clientIp})가 일시 잠금되었습니다. (${Math.ceil(
            ipStatus.banRemainingSeconds / 60
          )}분 후 자동 해제)`,
        });
      }

      const headerPin = cleanString(
        safeDecodeHeaderPin(req.headers["x-planner-pin"] || ""),
        512,
        ""
      );

      // 비활성화되거나 삭제된 초대 코드인지 먼저 확인하여 명확한 안내 제공
      const invStatus = findInviteStatus(headerPin, securityConfig);
      if (invStatus.status === "disabled") {
        return res.status(401).json({
          ok: false,
          requiresAuth: true,
          inviteDisabled: true,
          clientIp,
          error: "⏸️ 관리자에 의해 일시 비활성화된 초대 코드입니다. 관리자에게 활성화를 요청해주세요.",
        });
      }
      if (invStatus.status === "revoked") {
        return res.status(401).json({
          ok: false,
          requiresAuth: true,
          inviteRevoked: true,
          clientIp,
          error: "🗑️ 관리자에 의해 삭제(폐기)된 초대 코드입니다.",
        });
      }

      if (!headerPin || !verifyAccessPassword(headerPin, securityConfig)) {
        return res.status(401).json({
          ok: false,
          requiresAuth: true,
          clientIp,
          remainingAttempts: Math.max(0, MAX_PIN_FAILS - ipStatus.fails),
          error: "시작 페이지 비밀번호 또는 초대 코드 인증이 필요합니다.",
        });
      }

      return res.status(200).json(stripSensitiveFieldsForClient(existing || memoryFallback));
    }

    // =========================================================================
    // 2. POST 요청: 인증 / 초대코드 관리 / 관리자 설정 / 데이터 동기화
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
      const providedPin = cleanString(
        safeDecodeHeaderPin(
          req.headers["x-planner-pin"] || body.password || body.authPin || ""
        ),
        512,
        ""
      );

      // -----------------------------------------------------------------------
      // 🔓 IP 잠금 상태 확인 요청 (action === "checkIpStatus") — 카운트다운 완료 시 확인용
      // -----------------------------------------------------------------------
      if (action === "checkIpStatus") {
        const latestIp = getIpStatus(clientIp, securityConfig);
        return res.status(200).json({
          ok: true,
          ipBanned: latestIp.banned,
          clientIp,
          banExpiresAt: latestIp.banExpiresAt,
          banRemainingSeconds: latestIp.banRemainingSeconds,
          remainingAttempts: Math.max(0, MAX_PIN_FAILS - latestIp.fails),
        });
      }

      // -----------------------------------------------------------------------
      // 👑 관리자 전용 액션들 (PBKDF2-SHA512 마스터 해시 검증 또는 인증된 플래너 오너 권한)
      // -----------------------------------------------------------------------
      if (
        action === "adminLogin" ||
        action === "adminSetPrimaryPassword" ||
        action === "adminAddPassword" ||
        action === "adminDeletePassword" ||
        action === "adminUnbanIp"
      ) {
        const candidateAdminKey = cleanString(body.adminKey || "", 128, "");
        const isMasterAdmin = verifyAdminMasterKey(candidateAdminKey);
        const isSessionOwner =
          action === "adminUnbanIp" &&
          providedPin &&
          verifyAccessPassword(providedPin, securityConfig);

        if (!isMasterAdmin && !isSessionOwner) {
          if (ipStatus.fails >= MAX_PIN_FAILS + 3) {
            return res.status(403).json({
              ok: false,
              ipBanned: true,
              clientIp,
              banExpiresAt: ipStatus.banExpiresAt,
              banRemainingSeconds: ipStatus.banRemainingSeconds,
              error: `🚫 반복된 인증 실패로 현재 IP(${clientIp})에서의 접근이 일시 차단되었습니다.`,
            });
          }

          const updatedIp = registerIpFailure(clientIp, securityConfig);
          await persistSecurityConfigOnly(existing, securityConfig);

          if (updatedIp.banned) {
            return res.status(403).json({
              ok: false,
              ipBanned: true,
              clientIp,
              banExpiresAt: updatedIp.banExpiresAt,
              banRemainingSeconds: updatedIp.banRemainingSeconds,
              remainingAttempts: 0,
              error: `🚫 비밀번호 ${MAX_PIN_FAILS}회 오류로 현재 IP(${clientIp})가 10분간 일시 잠금되었습니다.`,
            });
          }

          return res.status(401).json({
            ok: false,
            remainingAttempts: Math.max(0, MAX_PIN_FAILS - updatedIp.fails),
            error: `관리자 비밀번호가 일치하지 않습니다. (남은 기회: ${Math.max(
              0,
              MAX_PIN_FAILS - updatedIp.fails
            )}회 / ${MAX_PIN_FAILS}회 실패 시 10분 일시 잠금)`,
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
            const oldIds = (securityConfig.accessEntries || [])
              .map((e) => String(e.id || ""))
              .filter(Boolean);
            const delSet = new Set([...(securityConfig.deletedPasswordIds || []), ...oldIds]);
            securityConfig.deletedPasswordIds = Array.from(delSet).slice(0, 200);
            securityConfig.primaryReplacedAt = Date.now();
            securityConfig.accessEntries = [newEntry];
          } else {
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
                ? "✅ 접속 비밀번호가 새 비밀번호로 변경되었습니다."
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
          const delSet = new Set([...(securityConfig.deletedPasswordIds || []), entryId]);
          securityConfig.deletedPasswordIds = Array.from(delSet).slice(0, 200);
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
            message: "🔓 IP 잠금이 즉시 해제되었습니다.",
            ...formatAdminClientPayload(securityConfig),
          });
        }
      }

      // -----------------------------------------------------------------------
      // 🎟️ 초대 코드 · 링크 관리 액션들 (생성 / 조회 / 활성·비활성 토글 / 메모 수정 / 삭제)
      // -----------------------------------------------------------------------
      if (
        action === "listInviteTickets" ||
        action === "generateInviteTicket" ||
        action === "createInviteCode" ||
        action === "toggleInviteTicket" ||
        action === "updateInviteLabel" ||
        action === "deleteInviteTicket"
      ) {
        const isAuthorized =
          verifyAccessPassword(providedPin, securityConfig) ||
          verifyAdminMasterKey(cleanString(body.adminKey || "", 128, ""));

        if (!isAuthorized) {
          return res.status(401).json({
            ok: false,
            error: "초대 코드를 관리하려면 먼저 로그인하거나 관리자 인증이 필요합니다.",
          });
        }

        if (action === "listInviteTickets") {
          return res.status(200).json({
            ok: true,
            ...formatAdminClientPayload(securityConfig),
          });
        }

        if (action === "generateInviteTicket" || action === "createInviteCode") {
          const currentList = Array.isArray(securityConfig.inviteTickets)
            ? securityConfig.inviteTickets
            : [];
          const nextNum = currentList.length + 1;
          const label = cleanString(
            body.label || `동행인 초대 #${nextNum}`,
            60,
            `동행인 초대 #${nextNum}`
          );

          const rawCustomCode = cleanString(body.customCode || "", 20, "");
          const code = rawCustomCode
            ? formatReadableInviteCode(rawCustomCode)
            : generateRandomShortCode(currentList);

          const now = Date.now();
          const id = `inv-${now}-${crypto.randomBytes(3).toString("hex")}`;
          const ticket = createSignedInviteTicket({ id, code, label, createdAt: now });

          const newInvite = normalizeInviteItem(
            {
              id,
              code,
              ticket,
              label,
              active: true,
              createdAt: now,
              createdAtText: new Date(now).toLocaleString("ko-KR"),
              expiresAt: now + 10 * 365 * 24 * 60 * 60 * 1000,
              useCount: 0,
              lastUsedAt: null,
              updatedAt: now,
            },
            0
          );

          // 만약 이전에 삭제 목록에 같은 코드가 있었다면 해제
          const codeNorm = normalizeInviteCode(code);
          securityConfig.revokedTickets = (securityConfig.revokedTickets || []).filter(
            (r) => r !== codeNorm && r !== ticket && r !== id
          );

          securityConfig.inviteTickets = [newInvite, ...currentList.slice(0, 99)];
          await persistSecurityConfigOnly(existing, securityConfig);

          return res.status(200).json({
            ok: true,
            ticket: newInvite.ticket,
            code: newInvite.code,
            invite: newInvite,
            message: `🎟️ '${newInvite.label}' 초대 코드(${newInvite.code})와 링크가 발급되었습니다!`,
            ...formatAdminClientPayload(securityConfig),
          });
        }

        if (action === "toggleInviteTicket") {
          const inviteId = cleanString(body.inviteId || body.ticket || "", 256, "");
          const list = Array.isArray(securityConfig.inviteTickets)
            ? securityConfig.inviteTickets
            : [];
          let toggledItem = null;

          securityConfig.inviteTickets = list.map((item) => {
            if (item.id === inviteId || item.ticket === inviteId || item.code === inviteId) {
              const nextActive =
                typeof body.active === "boolean" ? body.active : item.active === false;
              toggledItem = {
                ...item,
                active: nextActive,
                updatedAt: Date.now(),
              };
              return toggledItem;
            }
            return item;
          });

          if (!toggledItem) {
            return res.status(404).json({
              ok: false,
              error: "해당 초대 코드를 찾을 수 없습니다.",
            });
          }

          await persistSecurityConfigOnly(existing, securityConfig);
          return res.status(200).json({
            ok: true,
            invite: toggledItem,
            message: toggledItem.active
              ? `🟢 '${toggledItem.label}' (${toggledItem.code}) 초대 코드가 활성화되었습니다.`
              : `⚪ '${toggledItem.label}' (${toggledItem.code}) 초대 코드가 비활성화되었습니다. (해당 코드 접속 차단)`,
            ...formatAdminClientPayload(securityConfig),
          });
        }

        if (action === "updateInviteLabel") {
          const inviteId = cleanString(body.inviteId || body.ticket || "", 256, "");
          const newLabel = cleanString(body.label || "", 60, "");
          if (!newLabel) {
            return res.status(400).json({
              ok: false,
              error: "표기할 이름(메모)을 입력해주세요.",
            });
          }

          const list = Array.isArray(securityConfig.inviteTickets)
            ? securityConfig.inviteTickets
            : [];
          let updatedItem = null;

          securityConfig.inviteTickets = list.map((item) => {
            if (item.id === inviteId || item.ticket === inviteId || item.code === inviteId) {
              updatedItem = {
                ...item,
                label: newLabel,
                updatedAt: Date.now(),
              };
              return updatedItem;
            }
            return item;
          });

          if (!updatedItem) {
            return res.status(404).json({
              ok: false,
              error: "해당 초대 코드를 찾을 수 없습니다.",
            });
          }

          await persistSecurityConfigOnly(existing, securityConfig);
          return res.status(200).json({
            ok: true,
            invite: updatedItem,
            message: `🏷️ 초대 코드 메모가 '${newLabel}'(으)로 수정되었습니다.`,
            ...formatAdminClientPayload(securityConfig),
          });
        }

        if (action === "deleteInviteTicket") {
          const inviteId = cleanString(body.inviteId || body.ticket || "", 256, "");
          const list = Array.isArray(securityConfig.inviteTickets)
            ? securityConfig.inviteTickets
            : [];
          const target = list.find(
            (item) => item.id === inviteId || item.ticket === inviteId || item.code === inviteId
          );

          securityConfig.inviteTickets = list.filter(
            (item) => item.id !== inviteId && item.ticket !== inviteId && item.code !== inviteId
          );

          const revokedSet = new Set(securityConfig.revokedTickets || []);
          if (inviteId) revokedSet.add(inviteId);
          if (target) {
            if (target.id) revokedSet.add(target.id);
            if (target.ticket) revokedSet.add(target.ticket);
            if (target.code) revokedSet.add(normalizeInviteCode(target.code));
          }
          securityConfig.revokedTickets = Array.from(revokedSet).slice(0, 200);

          await persistSecurityConfigOnly(existing, securityConfig);
          return res.status(200).json({
            ok: true,
            message: target
              ? `🗑️ '${target.label}' (${target.code}) 초대 코드가 영구 삭제되었습니다.`
              : "🗑️ 초대 코드가 삭제되었습니다.",
            ...formatAdminClientPayload(securityConfig),
          });
        }
      }

      // -----------------------------------------------------------------------
      // 🎫 원클릭 초대 링크 / 초대 티켓 수락 요청 (action === "redeemInviteTicket")
      //    - 링크 클릭은 IP 차단 횟수에 카운트하지 않으며, 활성/비활성 상태를 정확히 판별
      // -----------------------------------------------------------------------
      if (action === "redeemInviteTicket") {
        const ticketCandidate = cleanString(
          safeDecodeHeaderPin(body.ticket || ""),
          512,
          ""
        );
        const invStatus = findInviteStatus(ticketCandidate, securityConfig);

        if (invStatus.status === "disabled") {
          return res.status(403).json({
            ok: false,
            inviteDisabled: true,
            clientIp,
            error: `⏸️ '${
              invStatus.matched?.label || "초대 코드"
            }' 코드는 현재 관리자에 의해 일시 비활성화되어 있습니다. 관리자에게 활성화를 요청해주세요.`,
          });
        }

        if (invStatus.status === "revoked") {
          return res.status(403).json({
            ok: false,
            inviteRevoked: true,
            clientIp,
            error: "🗑️ 관리자에 의해 삭제(폐기)된 초대 코드입니다.",
          });
        }

        if (invStatus.status === "active" && invStatus.matched) {
          recordInviteUsage(invStatus.matched, securityConfig);
          resetIpFailure(clientIp, securityConfig);
          await persistSecurityConfigOnly(existing, securityConfig);
          return res.status(200).json({
            ok: true,
            authenticated: true,
            ticket: invStatus.matched.ticket,
            code: invStatus.matched.code,
            label: invStatus.matched.label,
            clientIp,
            cloudData: stripSensitiveFieldsForClient(existing || memoryFallback),
            ...formatAdminClientPayload(securityConfig),
          });
        }

        return res.status(401).json({
          ok: false,
          clientIp,
          error:
            "유효하지 않은 초대 코드입니다. 시작 화면 입력창에 초대 코드(예: JP-XXXX) 또는 접속 비밀번호를 입력해주세요.",
        });
      }

      // -----------------------------------------------------------------------
      // 🚫 일반 요청 시 IP 일시 잠금 여부 확인 (10분 자동 해제 카운트다운 포함)
      // -----------------------------------------------------------------------
      if (ipStatus.banned) {
        return res.status(403).json({
          ok: false,
          ipBanned: true,
          clientIp,
          banExpiresAt: ipStatus.banExpiresAt,
          banRemainingSeconds: ipStatus.banRemainingSeconds,
          remainingAttempts: 0,
          error: `🚫 비밀번호/코드 ${MAX_PIN_FAILS}회 연속 오류로 현재 IP(${clientIp})가 일시 잠금되었습니다. (약 ${Math.ceil(
            ipStatus.banRemainingSeconds / 60
          )}분 후 자동 해제)`,
        });
      }

      // -----------------------------------------------------------------------
      // 🔑 시작 페이지 입장 검증 요청 (action === "authenticateEntry")
      //    - 접속 비밀번호, 단축 초대 코드(JP-XXXX), 초대 링크 URL, 관리자 마스터 키 모두 통합 지원!
      // -----------------------------------------------------------------------
      if (action === "authenticateEntry") {
        // 1) 먼저 초대 코드(JP-XXXX) 또는 초대 링크(URL/티켓)인지 확인
        const inviteStatus = findInviteStatus(providedPin, securityConfig);
        if (inviteStatus.status === "disabled") {
          return res.status(403).json({
            ok: false,
            inviteDisabled: true,
            ipBanned: false,
            clientIp,
            remainingAttempts: Math.max(0, MAX_PIN_FAILS - ipStatus.fails),
            error: `⏸️ 입력하신 초대 코드(${
              inviteStatus.matched?.code || ""
            })는 관리자에 의해 일시 비활성화된 상태입니다. 관리자에게 활성화를 요청해주세요.`,
          });
        }
        if (inviteStatus.status === "revoked") {
          return res.status(403).json({
            ok: false,
            inviteRevoked: true,
            ipBanned: false,
            clientIp,
            remainingAttempts: Math.max(0, MAX_PIN_FAILS - ipStatus.fails),
            error: "🗑️ 관리자에 의해 삭제(폐기)된 초대 코드입니다.",
          });
        }
        if (inviteStatus.status === "active" && inviteStatus.matched) {
          recordInviteUsage(inviteStatus.matched, securityConfig);
          resetIpFailure(clientIp, securityConfig);
          await persistSecurityConfigOnly(existing, securityConfig);
          return res.status(200).json({
            ok: true,
            authenticated: true,
            openedAdmin: false,
            usedInvite: true,
            sessionToken: `ticket:${inviteStatus.matched.ticket}`,
            inviteCode: inviteStatus.matched.code,
            inviteLabel: inviteStatus.matched.label,
            clientIp,
            cloudData: stripSensitiveFieldsForClient(existing || memoryFallback),
            ...formatAdminClientPayload(securityConfig),
          });
        }

        // 2) 관리자 전용 마스터 키를 입력한 경우 → 관리자 페이지 오픈 + 입장 허용
        if (verifyAdminMasterKey(providedPin)) {
          resetIpFailure(clientIp, securityConfig);
          await persistSecurityConfigOnly(existing, securityConfig);
          return res.status(200).json({
            ok: true,
            authenticated: true,
            openedAdmin: true,
            clientIp,
            cloudData: stripSensitiveFieldsForClient(existing || memoryFallback),
            ...formatAdminClientPayload(securityConfig),
          });
        }

        // 3) 일반 접속 비밀번호(기본 또는 추가된 비밀번호) 일치 확인
        if (verifyAccessPassword(providedPin, securityConfig)) {
          resetIpFailure(clientIp, securityConfig);
          await persistSecurityConfigOnly(existing, securityConfig);
          return res.status(200).json({
            ok: true,
            authenticated: true,
            openedAdmin: false,
            clientIp,
            cloudData: stripSensitiveFieldsForClient(existing || memoryFallback),
            ...formatAdminClientPayload(securityConfig),
          });
        }

        // 4) 모두 불일치 → 실패 횟수 증가 및 5회 도달 시 10분 일시 잠금
        const updatedIp = registerIpFailure(clientIp, securityConfig);
        await persistSecurityConfigOnly(existing, securityConfig);

        if (updatedIp.banned) {
          return res.status(403).json({
            ok: false,
            ipBanned: true,
            clientIp,
            banExpiresAt: updatedIp.banExpiresAt,
            banRemainingSeconds: updatedIp.banRemainingSeconds,
            remainingAttempts: 0,
            error: `🚫 비밀번호/초대코드 ${MAX_PIN_FAILS}회 연속 오류로 인해 현재 IP(${clientIp})가 10분간 일시 잠금되었습니다.`,
          });
        }

        const remaining = Math.max(0, MAX_PIN_FAILS - updatedIp.fails);
        return res.status(401).json({
          ok: false,
          ipBanned: false,
          clientIp,
          remainingAttempts: remaining,
          error: `비밀번호 또는 초대 코드가 일치하지 않습니다. (남은 기회: ${remaining}회 / ${MAX_PIN_FAILS}회 실패 시 10분 일시 잠금)`,
        });
      }

      // -----------------------------------------------------------------------
      // ☁️ 일반 일정·메모 저장 요청: 유효한 접속 비밀번호 또는 활성 초대코드 필수
      // -----------------------------------------------------------------------
      if (!providedPin || !verifyAccessPassword(providedPin, securityConfig)) {
        const invCheck = findInviteStatus(providedPin, securityConfig);
        return res.status(401).json({
          ok: false,
          requiresAuth: true,
          inviteDisabled: invCheck.status === "disabled",
          ipBanned: false,
          remainingAttempts: Math.max(0, MAX_PIN_FAILS - ipStatus.fails),
          error:
            invCheck.status === "disabled"
              ? "⏸️ 사용 중인 초대 코드가 관리자에 의해 비활성화되어 화면이 잠겼습니다."
              : "🔒 인증이 만료되었거나 비밀번호가 변경되었습니다. 다시 로그인해주세요.",
        });
      }

      // 🛡️ [수정 B] 빈 초기 기기가 기존 클라우드 데이터를 덮어쓰는 현상 방지 & 스마트 데이터 보존
      const incomingPins = Array.isArray(body.pins) ? body.pins : [];
      const incomingDays = Array.isArray(body.days) ? body.days : [];
      const incomingNotes = Array.isArray(body.notes) ? body.notes : [];
      const incomingChecklist = Array.isArray(body.checklist) ? body.checklist : [];

      const isExplicitReset = Boolean(body.explicitlyCleared);
      const isForceOverwrite = Boolean(body.forceOverwrite);
      const incomingHasMeaningful =
        incomingPins.length > 0 ||
        hasMeaningfulNotes(incomingNotes) ||
        hasMeaningfulChecklist(incomingChecklist);

      // 만약 Supabase 조회가 일시 실패했고 메모리 캐시도 비어있는 콜드스타트 상태라면:
      // 기존 클라우드 덮어쓰기는 막되, 503 에러 대신 메모리 캐시 보존 후 200 응답으로 정상 UX 유지
      if (supabaseFetchFailed && !existing && !isForceOverwrite) {
        if (incomingHasMeaningful || isExplicitReset) {
          const fallbackPayload = sanitizeSyncPayload(body, securityConfig);
          memoryFallback = fallbackPayload;
          securityConfigMemory = securityConfig;
          return res.status(200).json({
            ok: true,
            updatedAt: fallbackPayload.updatedAt,
            storage: "memory-fallback-protected-v4",
          });
        }
        return res.status(200).json({
          ok: true,
          skippedEmptyOnColdStart: true,
          updatedAt: Date.now(),
          storage: "memory-protected-noop-v4",
        });
      }

      const existingPins = existing && Array.isArray(existing.pins) ? existing.pins : [];
      const existingDays = existing && Array.isArray(existing.days) ? existing.days : [];
      const existingNotes = existing && Array.isArray(existing.notes) ? existing.notes : [];
      const existingChecklist = existing && Array.isArray(existing.checklist) ? existing.checklist : [];

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
      securityConfigMemory = securityConfig;

      let dbSaved = false;
      try {
        dbSaved = await saveToSupabase(sanitizedPayload);
      } catch {
        dbSaved = false;
      }

      return res.status(200).json({
        ok: true,
        dbSynced: dbSaved,
        updatedAt: sanitizedPayload.updatedAt,
        storage: dbSaved
          ? "supabase-couple-calendar-secured-v4"
          : "memory-fallback-secured-v4",
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
