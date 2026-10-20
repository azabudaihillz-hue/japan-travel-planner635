/**
 * Vercel Serverless Function: /api/sync
 *
 * couple-calendar-new (https://github.com/azabudaihillz-hue/couple-calendar-new) 에서 사용 중인
 * Supabase 실시간 데이터베이스(abjspnuohxouufkdjefs.supabase.co)를 활용하여
 * 맥북 · 내 핸드폰 · 여자친구 핸드폰 등 모든 기기에서 상시 실시간 동기화를 수행합니다.
 */

const SUPABASE_URL =
  process.env.SUPABASE_URL || "https://abjspnuohxouufkdjefs.supabase.co";
const SUPABASE_ANON_KEY =
  process.env.SUPABASE_ANON_KEY ||
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFianNwbnVvaHhvdXVma2RqZWZzIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODkzMDA5NzcsImV4cCI6MjEwNDg3Njk3N30.hVL3TRPwA1xalf1Tb2LiKJ58Q_DgBc5RWwFs2AfR890";

// couple_calendar 테이블은 YYYY-MM-DD 형식만 달력에 렌더링하고 memo에 '♥'가 있을 때만 D-Day로 잡으므로
// 전용 키 'JAPAN_TRAVEL_PLANNER_635' 와 memo: '' 를 사용하면 기존 커플 캘린더에 전혀 영향을 주지 않습니다.
const SYNC_ROW_KEY = "JAPAN_TRAVEL_PLANNER_635";

let memoryFallback = null;

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

  const res = await fetch(endpoint, {
    method: "GET",
    headers: getSupabaseHeaders({ "Cache-Control": "no-cache" }),
  });

  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`Supabase GET failed (${res.status}): ${errText}`);
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
    } catch (e) {
      // ignore parse error
    }
  }
  return null;
}

async function saveToSupabase(payload) {
  const endpoint = `${SUPABASE_URL}/rest/v1/couple_calendar?on_conflict=date`;
  const rowBody = {
    date: SYNC_ROW_KEY,
    memo: "",
    hae_shift: payload,
    hae_memo: JSON.stringify(payload),
  };

  const res = await fetch(endpoint, {
    method: "POST",
    headers: getSupabaseHeaders({
      Prefer: "resolution=merge-duplicates,return=minimal",
    }),
    body: JSON.stringify(rowBody),
  });

  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`Supabase UPSERT failed (${res.status}): ${errText}`);
  }
  return true;
}

module.exports = async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  try {
    if (req.method === "GET") {
      try {
        const cloudData = await fetchFromSupabase();
        if (cloudData) {
          memoryFallback = cloudData;
          return res.status(200).json(cloudData);
        }
      } catch (err) {
        if (memoryFallback) {
          return res.status(200).json(memoryFallback);
        }
      }
      return res.status(200).json(
        memoryFallback || {
          pins: [],
          notes: [],
          checklist: [],
          empty: true,
          updatedAt: 0,
        }
      );
    }

    if (req.method === "POST") {
      const body =
        typeof req.body === "string" ? JSON.parse(req.body) : req.body || {};

      // 빈 초기 기기가 기존 클라우드 데이터를 덮어쓰는 현상 방지
      const incomingPins = Array.isArray(body.pins) ? body.pins : [];
      if (incomingPins.length === 0 && !body.explicitlyCleared && !body.forceOverwrite) {
        try {
          const existing = await fetchFromSupabase();
          if (existing && Array.isArray(existing.pins) && existing.pins.length > 0) {
            return res.status(200).json({
              ok: false,
              skippedEmptyOverwrite: true,
              cloudData: existing,
            });
          }
        } catch (e) {
          // ignore check error
        }
      }

      const payload = {
        ...body,
        pins: incomingPins,
        updatedAt: body.updatedAt || Date.now(),
      };

      memoryFallback = payload;
      await saveToSupabase(payload);

      return res.status(200).json({
        ok: true,
        updatedAt: payload.updatedAt,
        storage: "supabase-couple-calendar",
      });
    }

    return res.status(405).json({ error: "Method not allowed" });
  } catch (err) {
    return res.status(500).json({
      error: "Sync error",
      details: err.message,
    });
  }
};
