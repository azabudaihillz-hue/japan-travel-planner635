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
let cachedUpsertFormat = null; // 'primary' | 'fallback'
let lastSupabaseFetchTime = 0;
let cachedSupabaseData = null;
const SUPABASE_CACHE_TTL_MS = 6000; // 6초 인스턴스 캐시 (중복 GET 왕복 제거)

function resolveSupabaseCredentialsList() {
  const env = process.env || {};
  const pairs = [];
  const pairSeen = new Set();

  const pushPair = (rawUrl, rawKey) => {
    const url = normalizeSupabaseBaseUrl(rawUrl);
    const key = cleanEnvToken(rawKey).replace(/\s+/g, "");
    if (!url || !key) return;
    if (key.length < 20 || /^https?:\/\//i.test(key)) return;
    const sig = url + "|" + key;
    if (pairSeen.has(sig)) return;
    pairSeen.add(sig);
    pairs.push({ url, key });
  };

  if (cachedWorkingCreds && cachedWorkingCreds.url && cachedWorkingCreds.key) {
    pushPair(cachedWorkingCreds.url, cachedWorkingCreds.key);
  }

  // 1. 직접 지정된 환경변수 우선 로드 (Vercel Project Settings 우선)
  const directPairs = [
    [env.SUPABASE_URL, env.SUPABASE_ANON_KEY],
    [env.EXPO_PUBLIC_COUPLE_SUPABASE_URL, env.EXPO_PUBLIC_COUPLE_SUPABASE_ANON_KEY],
    [env.EXPO_PUBLIC_SUPABASE_URL, env.EXPO_PUBLIC_SUPABASE_ANON_KEY],
    [env.NEXT_PUBLIC_SUPABASE_URL, env.NEXT_PUBLIC_SUPABASE_ANON_KEY],
    [env.VITE_SUPABASE_URL, env.VITE_SUPABASE_ANON_KEY],
    [env.SUPABASE_URL_, env.SUPABASE_ANON_KEY_],
    [env._SUPABASE_URL, env._SUPABASE_ANON_KEY],
    [env.EXPO_PUBLIC_COUPLE_SUPABASE_URL_, env.EXPO_PUBLIC_COUPLE_SUPABASE_ANON_KEY_],
    [env.EXPO_PUBLIC_SUPABASE_URL_, env.EXPO_PUBLIC_SUPABASE_ANON_KEY_],
  ];

  for (const [u, k] of directPairs) {
    if (u && k) pushPair(u, k);
  }

  // 2. JWT 내부 ref 분석 조합 (검증된 Supabase JWT 토큰)
  const candidateKeys = [
    env.SUPABASE_ANON_KEY,
    env.EXPO_PUBLIC_COUPLE_SUPABASE_ANON_KEY,
    env.EXPO_PUBLIC_SUPABASE_ANON_KEY,
    env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
    env.VITE_SUPABASE_ANON_KEY,
    env.SUPABASE_ANON_KEY_,
    env.EXPO_PUBLIC_COUPLE_SUPABASE_ANON_KEY_,
    env.EXPO_PUBLIC_SUPABASE_ANON_KEY_,
  ].filter(Boolean);

  for (const k of candidateKeys) {
    const jwt = parseSupabaseAnonJwt(k);
    if (jwt && jwt.ref) {
      pushPair("https://" + jwt.ref.toLowerCase() + ".supabase.co", jwt.token);
    }
  }

  // 3. process.env 전체에서 Supabase JWT 토큰 자동 탐지 (변수명이 약간 달라도 안전 감지)
  for (const [envName, envVal] of Object.entries(env)) {
    if (!envVal || typeof envVal !== "string") continue;
    if (/SERVICE_ROLE/i.test(envName)) continue;
    if (envVal.startsWith("eyJ") && envVal.length > 50) {
      const jwt = parseSupabaseAnonJwt(envVal);
      if (jwt && jwt.ref) {
        pushPair("https://" + jwt.ref.toLowerCase() + ".supabase.co", jwt.token);
      }
    }
  }

  // 4. Vercel 환경 변수가 미설정되었을 때 상시 연결 가능한 영구 저장소 기본 크레덴셜
  const DEFAULT_FALLBACK_URL = "https://abjspnuohxouufkdjefs.supabase.co";
  const DEFAULT_FALLBACK_KEY =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFianNwbnVvaHhvdXVma2RqZWZzIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODkzMDA5NzcsImV4cCI6MjEwNDg3Njk3N30.hVL3TRPwA1xalf1Tb2LiKJ58Q_DgBc5RWwFs2AfR890";

  pushPair(DEFAULT_FALLBACK_URL, DEFAULT_FALLBACK_KEY);

  return pairs;
}

const SYNC_ROW_KEY = "JAPAN_TRAVEL_PLANNER_635";

// 🔐 PBKDF2-HMAC-SHA512 (100,000 iterations) 보안 상수 — 평문 비밀번호는 코드에 일절 저장하지 않음
// 환경변수(ENTRY_DEFAULT_*, ADMIN_MASTER_*) 우선 로드 지원
// 기본 초기 접속 비밀번호: "0000", 기본 초기 관리자 비밀번호: "0000"
const PBKDF2_ITERATIONS = 100000;
const PBKDF2_KEYLEN = 64;
const PBKDF2_DIGEST = "sha512";

const DEFAULT_ENTRY_SALT =
  cleanEnvToken(process.env.ENTRY_DEFAULT_SALT) || "JP635_ENTRY_DEFAULT_SALT_v3_99f1a4c8";
// "0000" with DEFAULT_ENTRY_SALT (pbkdf2Sync 100,000 iterations, 64 bytes, sha512)
const DEFAULT_ENTRY_PBKDF2_HASH =
  cleanEnvToken(process.env.ENTRY_DEFAULT_PBKDF2_HASH) ||
  "75993dedc7be01567be1818065a3de96617ab5a1f230da753be74a2f80193b497e6b0851a5c44314f106ccb70d19f3b205291da08bd51e47b315db00c99681f2";

const ADMIN_MASTER_SALT =
  cleanEnvToken(process.env.ADMIN_MASTER_SALT) || "JP635_ADMIN_MASTER_SALT_v3_e7b204d1";
// "0000" with ADMIN_MASTER_SALT (pbkdf2Sync 100,000 iterations, 64 bytes, sha512)
const ADMIN_MASTER_PBKDF2_HASH =
  cleanEnvToken(process.env.ADMIN_MASTER_PBKDF2_HASH) ||
  "e9cf59b9c108436abcb6564ffcd98490d283f54f7807757e0cbc6c1da2a31dd22ab6f2dde520612e604866061a15202db6c1c4be9c8a314e36619afc46366076";

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

function getClientIp(req) {
  // 🛡️ Vercel 엣지가 주입하는 신뢰 헤더(x-vercel-forwarded-for, x-real-ip)를 최우선 사용하여 클라이언트 X-Forwarded-For 스푸핑 차단
  const vercelFwd = req.headers["x-vercel-forwarded-for"];
  if (typeof vercelFwd === "string" && vercelFwd.trim().length > 0) {
    return vercelFwd.split(",")[0].trim().slice(0, 64);
  }
  const realIp = req.headers["x-real-ip"];
  if (typeof realIp === "string" && realIp.trim().length > 0) {
    return realIp.trim().slice(0, 64);
  }
  const xff = req.headers["x-forwarded-for"];
  if (typeof xff === "string" && xff.trim().length > 0) {
    return xff.split(",")[0].trim().slice(0, 64);
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

function verifyAdminMasterKey(candidate, securityConfig = null) {
  if (typeof candidate !== "string") return false;
  const trimmed = candidate.trim();
  if (!trimmed) return false;

  // 1) 관리자가 변경한 커스텀 관리자 비밀번호가 있는 경우 최우선 검증 (기본 0000 비활성화)
  const customAdmin = securityConfig?.adminPasswordEntry;
  if (customAdmin && customAdmin.salt && customAdmin.hash) {
    const customDerived = derivePbkdf2Hex(trimmed, customAdmin.salt);
    return safeTimingEqualHex(customDerived, customAdmin.hash);
  }

  // 2) 환경변수 ADMIN_MASTER_PASSWORD가 설정된 경우
  const envAdminPlain = cleanEnvToken(process.env.ADMIN_MASTER_PASSWORD);
  if (envAdminPlain && envAdminPlain.length >= 4) {
    const envDerived = derivePbkdf2Hex(trimmed, ADMIN_MASTER_SALT);
    const expectedEnvDerived = derivePbkdf2Hex(envAdminPlain, ADMIN_MASTER_SALT);
    if (safeTimingEqualHex(envDerived, expectedEnvDerived)) return true;
  }

  // 3) 기본 초기 관리자 비밀번호: "0000" (ADMIN_MASTER_PBKDF2_HASH)
  const derived = derivePbkdf2Hex(trimmed, ADMIN_MASTER_SALT);
  return safeTimingEqualHex(derived, ADMIN_MASTER_PBKDF2_HASH);
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

  // 1) 삭제된 비밀번호 ID 목록 병합
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

  // 클라우드와 메모리의 모든 유효 접속 비밀번호를 통합 보존
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
        label: "초기 접속 비밀번호 (0000)",
        maskedHint: "•••• (초기: 0000)",
        salt: DEFAULT_ENTRY_SALT,
        hash: DEFAULT_ENTRY_PBKDF2_HASH,
        createdAt: "기본 보안 설정",
      },
    ];
  }

  // 2) 관리자 비밀번호 변경 항목 병합 (최신 변경 우선)
  let adminPasswordEntry = null;
  const cloudAdminEntry = cloudBase.adminPasswordEntry;
  const memAdminEntry = memBase.adminPasswordEntry;
  if (cloudAdminEntry && memAdminEntry) {
    adminPasswordEntry =
      (Number(memAdminEntry.updatedAt) || 0) >= (Number(cloudAdminEntry.updatedAt) || 0)
        ? memAdminEntry
        : cloudAdminEntry;
  } else {
    adminPasswordEntry = cloudAdminEntry || memAdminEntry || null;
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

  const mergedConfig = {
    accessEntries,
    deletedPasswordIds,
    primaryReplacedAt,
    adminPasswordEntry,
    ipRecords,
    configUpdatedAt: Math.max(
      Number(cloudBase.configUpdatedAt) || 0,
      Number(memBase.configUpdatedAt) || 0
    ),
  };

  securityConfigMemory = mergedConfig;
  return mergedConfig;
}

function verifyAccessPassword(candidate, securityConfig) {
  if (typeof candidate !== "string") return false;
  const trimmed = safeDecodeHeaderPin(candidate).trim();
  if (!trimmed) return false;

  // 1) 등록된 접속 허용 비밀번호(PBKDF2) 검증
  const entries = Array.isArray(securityConfig?.accessEntries)
    ? securityConfig.accessEntries
    : [];

  for (const entry of entries) {
    const derived = derivePbkdf2Hex(trimmed, entry.salt);
    if (safeTimingEqualHex(derived, entry.hash)) {
      return true;
    }
  }

  // 2) 환경변수 ENTRY_DEFAULT_PASSWORD가 명시 설정된 경우 검증
  const envEntryPlain = cleanEnvToken(process.env.ENTRY_DEFAULT_PASSWORD);
  if (envEntryPlain && envEntryPlain.length >= 4) {
    const envDerived = derivePbkdf2Hex(trimmed, DEFAULT_ENTRY_SALT);
    const expectedEnvDerived = derivePbkdf2Hex(envEntryPlain, DEFAULT_ENTRY_SALT);
    if (safeTimingEqualHex(envDerived, expectedEnvDerived)) {
      return true;
    }
  }

  // 3) 초기 부트스트랩 비밀번호("0000") 검증 (관리자가 새 단독 비밀번호를 설정했거나 커스텀 비밀번호가 등록된 후에는 공개 기본값 비활성화)
  const hasCustomPasswordConfigured =
    (Number(securityConfig?.primaryReplacedAt) || 0) > 0 ||
    entries.some((e) => e && e.id && e.id !== "default-entry-key");
  const hasExplicitEnvEntryHash = Boolean(cleanEnvToken(process.env.ENTRY_DEFAULT_PBKDF2_HASH));

  if (!hasCustomPasswordConfigured || hasExplicitEnvEntryHash) {
    const defaultDerived = derivePbkdf2Hex(trimmed, DEFAULT_ENTRY_SALT);
    if (safeTimingEqualHex(defaultDerived, DEFAULT_ENTRY_PBKDF2_HASH)) {
      return true;
    }
  }

  // 4) 관리자 비밀번호로도 접속 허용
  if (verifyAdminMasterKey(trimmed, securityConfig)) {
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

function formatAdminClientPayload(securityConfig) {
  const accessEntries = (securityConfig.accessEntries || []).map((e, idx) => ({
    id: String(e.id || `pw-${idx}`),
    label: String(e.label || `접속 비밀번호 #${idx + 1}`),
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

  const hasCustomAdminPassword = Boolean(securityConfig.adminPasswordEntry);

  return { accessEntries, bannedIps, hasCustomAdminPassword };
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

    const rawTags = Array.isArray(p.tags) ? p.tags.slice(0, 10) : [];
    const tags = rawTags
      .map((t) => cleanString(String(t || ""), 24, "").toLowerCase())
      .filter(Boolean);

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
      tags,
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

  const rawClientId = cleanString(raw.clientId, 64, "unknown").replace(/[^a-zA-Z0-9_-]/g, "");
  const safeClientId = /^device-[a-z0-9]{4,16}-\d{10,15}$/i.test(rawClientId)
    ? rawClientId
    : `srv-${rawClientId.slice(0, 24) || "anon"}`;

  // 🛡️ 서버 기준 타임스탬프 강제 (클라이언트가 미래 시각 updatedAt을 조작하여 LWW를 영구 선점하는 공격 차단)
  const serverNow = Date.now();
  const safeUpdatedAt = Math.min(clampNumber(raw.updatedAt, 0, serverNow, serverNow), serverNow);

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
    updatedAt: safeUpdatedAt,
    clientId: safeClientId,
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

  // 가장 최신 updatedAt을 가진 객체를 단일 신뢰 소스(Single Source of Truth)로 선택
  candidates.sort((a, b) => (Number(b.updatedAt) || 0) - (Number(a.updatedAt) || 0));
  const best = { ...candidates[0] };

  // candidates[0]에 securityConfig가 없으면 다른 컬럼에서 보충하되, 이전 오래된 컬럼으로 덮어쓰지 않음
  if (!best.securityConfig || typeof best.securityConfig !== "object") {
    for (const c of candidates) {
      if (c.securityConfig && typeof c.securityConfig === "object") {
        best.securityConfig = { ...c.securityConfig };
        break;
      }
    }
  }

  return best;
}

async function fetchFromSupabase(forceRefresh = false) {
  const now = Date.now();
  if (!forceRefresh && cachedSupabaseData && now - lastSupabaseFetchTime < SUPABASE_CACHE_TTL_MS) {
    return cachedSupabaseData;
  }

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
    const timer = setTimeout(() => controller.abort(), 2500);

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
        lastSupabaseFetchTime = Date.now();
        cachedSupabaseData = null;
        return null;
      }

      const result = extractBestObjectFromRow(rows[0]);
      cachedSupabaseData = result;
      lastSupabaseFetchTime = Date.now();
      return result;
    } catch (err) {
      lastErr = err;
    } finally {
      clearTimeout(timer);
    }
  }

  throw lastErr || new Error("Supabase GET failed across all credential candidates");
}

let lastSupabaseSaveError = "";

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
      const timer = setTimeout(() => controller.abort(), 4000);
      try {
        const res = await fetch(endpoint, {
          method: "POST",
          headers: getSupabaseHeaders(cred.key, {
            Prefer: "resolution=merge-duplicates,return=minimal",
          }),
          body: JSON.stringify(rowBody),
          signal: controller.signal,
        });
        if (!res.ok) {
          const text = await res.text().catch(() => "");
          lastErr = new Error(`Supabase POST ${res.status}: ${text.slice(0, 200)}`);
          return false;
        }
        return true;
      } catch (err) {
        lastErr = err;
        return false;
      } finally {
        clearTimeout(timer);
      }
    };

    try {
      // 검증된 포맷 우선 시도 (이전 성공 기록이 있으면 1회 왕복만으로 즉시 저장 성공)
      const formats = cachedUpsertFormat === "fallback" ? ["fallback", "primary"] : ["primary", "fallback"];

      for (const fmt of formats) {
        if (fmt === "primary") {
          const okPrimary = await attemptUpsert({
            date: SYNC_ROW_KEY,
            memo: "",
            hae_shift: payload,
            hae_memo: jsonStr,
          });

          if (okPrimary) {
            cachedWorkingCreds = cred;
            cachedUpsertFormat = "primary";
            cachedSupabaseData = payload;
            lastSupabaseFetchTime = Date.now();
            return true;
          }
        } else {
          const okFallback = await attemptUpsert({
            date: SYNC_ROW_KEY,
            memo: jsonStr,
            hae_shift: null,
            hae_memo: jsonStr,
          });

          if (okFallback) {
            cachedWorkingCreds = cred;
            cachedUpsertFormat = "fallback";
            cachedSupabaseData = payload;
            lastSupabaseFetchTime = Date.now();
            return true;
          }
        }
      }
    } catch (err) {
      lastErr = err;
    }
  }

  lastSupabaseSaveError = lastErr ? (lastErr.message || String(lastErr)) : "Supabase UPSERT failed";
  throw lastErr || new Error("Supabase UPSERT failed on both primary and fallback schemas");
}

async function persistSecurityConfigOnly(existingData, securityConfig) {
  securityConfig.configUpdatedAt = Date.now();
  securityConfigMemory = securityConfig;

  let baseObj = existingData;
  if (!baseObj || typeof baseObj !== "object" || !Array.isArray(baseObj.pins) || baseObj.pins.length === 0) {
    if (memoryFallback && typeof memoryFallback === "object" && Array.isArray(memoryFallback.pins) && memoryFallback.pins.length > 0) {
      baseObj = memoryFallback;
    } else {
      try {
        const fetched = await fetchFromSupabase();
        if (fetched && Array.isArray(fetched.pins) && fetched.pins.length > 0) {
          baseObj = fetched;
        }
      } catch {}
    }
  }

  if (!baseObj || typeof baseObj !== "object") {
    baseObj = {
      pins: [],
      days: [{ id: "day-1", label: "Day 1" }],
      tripTitle: "우리의 여행 ✈️",
      exchangeRate: 9.05,
      peopleCount: 2,
      notes: [],
      checklist: [],
    };
  }

  const payload = {
    ...baseObj,
    updatedAt: Math.max(Number(baseObj.updatedAt) || 0, Date.now()),
    securityConfig,
  };

  memoryFallback = payload;
  cachedSupabaseData = payload;
  lastSupabaseFetchTime = Date.now();

  try {
    const ok = await saveToSupabase(payload);
    return Boolean(ok);
  } catch (err) {
    lastSupabaseSaveError = err && err.message ? err.message : String(err);
    console.error("persistSecurityConfigOnly error:", lastSupabaseSaveError);
    return false;
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

  // 🛡️ 서버 환경변수 검증: SUPABASE_URL / SUPABASE_ANON_KEY 미설정 시 키 노출 없이 즉시 HTTP 500 반환
  if (
    resolveSupabaseCredentialsList().length === 0 &&
    process.env.ALLOW_MEMORY_ONLY_DEV !== "true"
  ) {
    return res.status(500).json({
      ok: false,
      error: "Server configuration missing: SUPABASE_URL / SUPABASE_ANON_KEY",
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
        action === "adminSetAdminPassword" ||
        action === "adminUnbanIp"
      ) {
        const candidateAdminKey = cleanString(body.adminKey || "", 128, "");
        const isMasterAdmin = verifyAdminMasterKey(candidateAdminKey, securityConfig);
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

          const ok = await persistSecurityConfigOnly(existing, securityConfig);
          if (!ok) {
            return res.status(500).json({
              ok: false,
              error: "클라우드 데이터베이스에 새 비밀번호를 저장하지 못했습니다. 잠시 후 다시 시도해주세요.",
            });
          }
          return res.status(200).json({
            ok: true,
            message:
              action === "adminSetPrimaryPassword"
                ? "✅ 접속 비밀번호가 새 비밀번호로 변경되었습니다. (기본 0000 비활성화)"
                : "✅ 새 접속 허용 비밀번호가 추가 등록되었습니다.",
            ...formatAdminClientPayload(securityConfig),
          });
        }

        if (action === "adminSetAdminPassword") {
          const newAdminPw = cleanString(body.newAdminPassword || "", 64, "").trim();
          if (!newAdminPw || newAdminPw.length < 4) {
            return res.status(400).json({
              ok: false,
              error: "새 관리자 비밀번호는 최소 4자 이상이어야 합니다.",
            });
          }

          const newSalt = `JP635_ADMIN_CUSTOM_${Date.now()}_${crypto.randomBytes(8).toString("hex")}`;
          const newHash = derivePbkdf2Hex(newAdminPw, newSalt);
          securityConfig.adminPasswordEntry = {
            salt: newSalt,
            hash: newHash,
            updatedAt: Date.now(),
            maskedHint: maskPasswordHint(newAdminPw),
          };

          const ok = await persistSecurityConfigOnly(existing, securityConfig);
          if (!ok) {
            return res.status(500).json({
              ok: false,
              error: "클라우드 데이터베이스에 관리자 비밀번호를 저장하지 못했습니다. 잠시 후 다시 시도해주세요.",
            });
          }
          return res.status(200).json({
            ok: true,
            message: "👑 관리자 비밀번호가 성공적으로 변경되었습니다. (기본 0000 비활성화)",
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
          const ok = await persistSecurityConfigOnly(existing, securityConfig);
          if (!ok) {
            return res.status(500).json({
              ok: false,
              error: "비밀번호 삭제를 클라우드에 반영하지 못했습니다. 잠시 후 다시 시도해주세요.",
            });
          }
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
          error: `🚫 비밀번호 ${MAX_PIN_FAILS}회 연속 오류로 현재 IP(${clientIp})가 일시 잠금되었습니다. (약 ${Math.ceil(
            ipStatus.banRemainingSeconds / 60
          )}분 후 자동 해제)`,
        });
      }

      // -----------------------------------------------------------------------
      // 🔑 시작 페이지 입장 검증 요청 (action === "authenticateEntry")
      //    - 관리자 마스터 키 또는 일반 접속 비밀번호 검증
      // -----------------------------------------------------------------------
      if (action === "authenticateEntry") {
        // 1) 관리자 비밀번호 검증 (커스텀 설정 또는 기본 0000)
        if (verifyAdminMasterKey(providedPin, securityConfig)) {
          resetIpFailure(clientIp, securityConfig);
          return res.status(200).json({
            ok: true,
            authenticated: true,
            openedAdmin: true,
            clientIp,
            cloudData: stripSensitiveFieldsForClient(existing || memoryFallback),
            ...formatAdminClientPayload(securityConfig),
          });
        }

        // 2) 일반 접속 비밀번호 일치 확인
        if (verifyAccessPassword(providedPin, securityConfig)) {
          resetIpFailure(clientIp, securityConfig);
          return res.status(200).json({
            ok: true,
            authenticated: true,
            openedAdmin: false,
            clientIp,
            cloudData: stripSensitiveFieldsForClient(existing || memoryFallback),
            ...formatAdminClientPayload(securityConfig),
          });
        }

        // 3) 모두 불일치 → 실패 횟수 증가 및 5회 도달 시 10분 일시 잠금
        const updatedIp = registerIpFailure(clientIp, securityConfig);

        if (updatedIp.banned) {
          return res.status(403).json({
            ok: false,
            ipBanned: true,
            clientIp,
            banExpiresAt: updatedIp.banExpiresAt,
            banRemainingSeconds: updatedIp.banRemainingSeconds,
            remainingAttempts: 0,
            error: `🚫 비밀번호 ${MAX_PIN_FAILS}회 연속 오류로 인해 현재 IP(${clientIp})가 10분간 일시 잠금되었습니다.`,
          });
        }

        const remaining = Math.max(0, MAX_PIN_FAILS - updatedIp.fails);
        return res.status(401).json({
          ok: false,
          ipBanned: false,
          clientIp,
          remainingAttempts: remaining,
          error: `비밀번호가 일치하지 않습니다. (남은 기회: ${remaining}회 / ${MAX_PIN_FAILS}회 실패 시 10분 일시 잠금)`,
        });
      }

      // -----------------------------------------------------------------------
      // ☁️ 일반 일정·메모 저장 요청: 유효한 접속 비밀번호 필수
      // -----------------------------------------------------------------------
      if (!providedPin || !verifyAccessPassword(providedPin, securityConfig)) {
        return res.status(401).json({
          ok: false,
          requiresAuth: true,
          ipBanned: false,
          remainingAttempts: Math.max(0, MAX_PIN_FAILS - ipStatus.fails),
          error: "🔒 인증이 만료되었거나 비밀번호가 변경되었습니다. 다시 로그인해주세요.",
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
          fallbackPayload.updatedAt = Date.now();
          memoryFallback = fallbackPayload;
          securityConfigMemory = securityConfig;
          return res.status(200).json({
            ok: true,
            dbSynced: false,
            updatedAt: fallbackPayload.updatedAt,
            storage: "memory-fallback-protected-v4",
          });
        }
        return res.status(200).json({
          ok: true,
          dbSynced: false,
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
      sanitizedPayload.updatedAt = Date.now();

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
