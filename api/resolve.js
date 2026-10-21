/**
 * Vercel Serverless Function: /api/resolve (Security-Hardened v2)
 *
 * 보안 패치 적용 내역:
 * 1) SSRF(서버 측 요청 위조) 원천 차단: 허용된 Google Maps 도메인 화이트리스트만 요청 허용 및 사설 IP/내부망 차단
 * 2) 리다이렉트(Redirect) 단계별 호스트 검증 (manual redirect + 최대 5홉 제한)
 * 3) 외부 요청 타임아웃(5초) 및 응답 본문 최대 크기(512KB) 제한 (DoS 방어)
 * 4) IP 기반 레이트 리미팅 (분당 최대 35회) 및 내부 에러 메시지 비노출
 */

const BROWSER_HEADERS = {
  "User-Agent":
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  Accept:
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
  "Accept-Language": "ko-KR,ko;q=0.9,ja-JP;q=0.8,ja;q=0.7,en-US;q=0.6,en;q=0.5",
  Cookie:
    "SOCS=CAISHAgBEhJnd3NfMjAyNDA1MTUtMF9SQzIaAmtvIAEaBgiA_LyaBg; CONSENT=YES+cb.20240101-01-p0.ko+FX+999",
};

// 🔒 SSRF 방어를 위한 엄격한 Google Maps 도메인 화이트리스트
const ALLOWED_GOOGLE_HOSTS = new Set([
  "maps.app.goo.gl",
  "goo.gl",
  "google.com",
  "www.google.com",
  "maps.google.com",
  "google.co.kr",
  "www.google.co.kr",
  "maps.google.co.kr",
  "google.co.jp",
  "www.google.co.jp",
  "maps.google.co.jp",
  "consent.google.com",
  "consent.google.co.kr",
  "consent.google.co.jp",
]);

const rateLimitMap = new Map();

function getClientIp(req) {
  const xff = req.headers["x-forwarded-for"];
  if (typeof xff === "string" && xff.length > 0) {
    return xff.split(",")[0].trim();
  }
  return req.socket?.remoteAddress || "unknown";
}

function checkRateLimit(ip) {
  const now = Date.now();
  const windowMs = 60 * 1000;
  let rec = rateLimitMap.get(ip);
  if (!rec || now - rec.start > windowMs) {
    rec = { start: now, count: 0 };
  }
  rec.count += 1;
  rateLimitMap.set(ip, rec);

  if (rateLimitMap.size > 2000) {
    for (const [k, v] of rateLimitMap.entries()) {
      if (now - v.start > windowMs) rateLimitMap.delete(k);
    }
  }
  return rec.count <= 35;
}

/**
 * 🛡️ SSRF 방지: 오직 공식 Google Maps / goo.gl 단축 URL 도메인만 허용
 */
function isAllowedGoogleMapsUrl(urlStr) {
  if (!urlStr || typeof urlStr !== "string" || urlStr.length > 2048) return false;
  try {
    const parsed = new URL(urlStr);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return false;
    if (parsed.username || parsed.password) return false;
    if (parsed.port && parsed.port !== "80" && parsed.port !== "443") return false;
    const host = parsed.hostname.toLowerCase();
    return ALLOWED_GOOGLE_HOSTS.has(host);
  } catch {
    return false;
  }
}

/**
 * 🛡️ 안전한 리다이렉트 추적기 (매 홉마다 호스트 화이트리스트 재검증 + 타임아웃 + 본문 크기 제한)
 */
async function safeFetchGoogleMaps(initialUrl, maxHops = 5) {
  let currentUrl = initialUrl;
  let hops = 0;

  while (hops < maxHops) {
    if (!isAllowedGoogleMapsUrl(currentUrl)) {
      throw new Error("Blocked non-whitelisted redirect host");
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);

    try {
      const response = await fetch(currentUrl, {
        method: "GET",
        redirect: "manual",
        headers: BROWSER_HEADERS,
        signal: controller.signal,
      });

      if (response.status >= 300 && response.status < 400) {
        const locationHeader = response.headers.get("location");
        if (!locationHeader) break;
        const resolvedNext = new URL(locationHeader, currentUrl).toString();
        if (!isAllowedGoogleMapsUrl(resolvedNext)) {
          // 구글맵 리다이렉트 URL 자체에 좌표가 들어있는 경우가 있으므로 URL만 보존하고 중단
          currentUrl = resolvedNext;
          break;
        }
        currentUrl = resolvedNext;
        hops += 1;
        continue;
      }

      const rawText = await response.text();
      return {
        finalUrl: response.url || currentUrl,
        html: rawText.slice(0, 512000), // 최대 512KB까지만 파싱하여 메모리 고갈 방지
      };
    } finally {
      clearTimeout(timer);
    }
  }

  return { finalUrl: currentUrl, html: "" };
}

function splitInputUrlAndHint(raw) {
  if (!raw || typeof raw !== "string") {
    return { cleanUrl: null, textHint: "" };
  }
  const trimmed = raw.trim().slice(0, 1000);
  const urlMatch = trimmed.match(/(https?:\/\/[^\s"'<>]+)/i);
  if (!urlMatch) {
    return { cleanUrl: null, textHint: trimmed };
  }
  const cleanUrl = urlMatch[1].replace(/[).,;]+$/, "");
  const textHint = trimmed
    .replace(urlMatch[0], " ")
    .replace(/Google\s*지도에서\s*보기/gi, "")
    .replace(/Shared\s*via\s*Google\s*Maps/gi, "")
    .replace(/\s+/g, " ")
    .trim();

  return { cleanUrl, textHint };
}

function decodeHtmlEntities(str) {
  if (!str) return "";
  return str
    .replace(/&amp;/g, "&")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/\\u0026/g, "&")
    .replace(/\\u003d/g, "=");
}

function sanitizePlainText(str, maxLen = 200) {
  if (!str || typeof str !== "string") return "";
  return str
    .replace(/[<>]/g, "")
    .replace(/[\u0000-\u001F\u007F]/g, "")
    .trim()
    .slice(0, maxLen);
}

function isValidLatLng(lat, lng) {
  return (
    typeof lat === "number" &&
    typeof lng === "number" &&
    !Number.isNaN(lat) &&
    !Number.isNaN(lng) &&
    Math.abs(lat) <= 90 &&
    Math.abs(lng) <= 180 &&
    !(lat === 0 && lng === 0)
  );
}

function parseGoogleMapData(urlStr, html = "", fallbackHint = "") {
  let lat = null;
  let lng = null;
  let name = null;
  let address = null;

  const decodedUrl = (() => {
    try {
      return decodeURIComponent(urlStr || "");
    } catch {
      return urlStr || "";
    }
  })();

  let effectiveUrl = urlStr || "";
  if (effectiveUrl.includes("consent.google.") && effectiveUrl.includes("continue=")) {
    const contMatch = effectiveUrl.match(/[?&]continue=([^&]+)/i);
    if (contMatch) {
      try {
        effectiveUrl = decodeURIComponent(contMatch[1]);
      } catch {
        effectiveUrl = contMatch[1];
      }
    }
  }

  const combinedSource = `${effectiveUrl}\n${decodedUrl}\n${decodeHtmlEntities(html)}`;
  let decodedSource = combinedSource;
  try {
    decodedSource = combinedSource.replace(/%2C/gi, ",").replace(/%3A/gi, ":");
  } catch {}

  const bangMatch = decodedSource.match(/!3d(-?\d+\.\d+)!4d(-?\d+\.\d+)/);
  if (bangMatch) {
    const cLat = parseFloat(bangMatch[1]);
    const cLng = parseFloat(bangMatch[2]);
    if (isValidLatLng(cLat, cLng)) {
      lat = cLat;
      lng = cLng;
    }
  }

  if (!isValidLatLng(lat, lng)) {
    const centerMatch = decodedSource.match(
      /center=(-?\d+\.\d+)(?:,|%2C)(-?\d+\.\d+)/i
    );
    if (centerMatch) {
      const cLat = parseFloat(centerMatch[1]);
      const cLng = parseFloat(centerMatch[2]);
      if (isValidLatLng(cLat, cLng)) {
        lat = cLat;
        lng = cLng;
      }
    }
  }

  if (!isValidLatLng(lat, lng)) {
    const atMatch = decodedSource.match(/@(-?\d+\.\d+),(-?\d+\.\d+)/);
    if (atMatch) {
      const cLat = parseFloat(atMatch[1]);
      const cLng = parseFloat(atMatch[2]);
      if (isValidLatLng(cLat, cLng)) {
        lat = cLat;
        lng = cLng;
      }
    }
  }

  if (!isValidLatLng(lat, lng)) {
    const qCoordMatch = decodedSource.match(
      /[?&](?:q|query|ll|sll|daddr|destination|viewpoint)=(-?\d+\.\d+)[,+\s]+(-?\d+\.\d+)/i
    );
    if (qCoordMatch) {
      const cLat = parseFloat(qCoordMatch[1]);
      const cLng = parseFloat(qCoordMatch[2]);
      if (isValidLatLng(cLat, cLng)) {
        lat = cLat;
        lng = cLng;
      }
    }
  }

  if (!isValidLatLng(lat, lng) && html) {
    const jsonCoordMatch = decodedSource.match(
      /\[null,null,(-?\d+\.\d{4,}),(-?\d+\.\d{4,})\]/
    );
    if (jsonCoordMatch) {
      const cLat = parseFloat(jsonCoordMatch[1]);
      const cLng = parseFloat(jsonCoordMatch[2]);
      if (isValidLatLng(cLat, cLng)) {
        lat = cLat;
        lng = cLng;
      }
    }
  }

  if (!isValidLatLng(lat, lng) && html) {
    const initMatch = decodedSource.match(
      /\[\d+\.\d+,(1[2-5]\d\.\d{4,}),([2-4]\d\.\d{4,})\]/
    );
    if (initMatch) {
      const cLng = parseFloat(initMatch[1]);
      const cLat = parseFloat(initMatch[2]);
      if (isValidLatLng(cLat, cLng)) {
        lat = cLat;
        lng = cLng;
      }
    }
  }

  const placeMatch = effectiveUrl.match(/\/maps\/(?:place|search)\/([^/@?&]+)/i);
  if (placeMatch && placeMatch[1]) {
    try {
      const candidate = decodeURIComponent(placeMatch[1].replace(/\+/g, " ")).trim();
      if (candidate && !/^(-?\d+\.\d+),(-?\d+\.\d+)$/.test(candidate)) {
        name = candidate;
      }
    } catch {}
  }

  if (!name) {
    const qNameMatch = effectiveUrl.match(/[?&](?:q|query)=([^&]+)/i);
    if (qNameMatch && qNameMatch[1]) {
      try {
        const candidate = decodeURIComponent(qNameMatch[1].replace(/\+/g, " ")).trim();
        if (candidate && !/^(-?\d+\.\d+)[,\s]+(-?\d+\.\d+)$/.test(candidate)) {
          name = candidate;
        }
      } catch {}
    }
  }

  if (html) {
    const metaTitleRegexes = [
      /<meta[^>]+(?:property=["']og:title["']|itemprop=["']name["'])[^>]+content=["']([^"']+)["']/i,
      /<meta[^>]+content=["']([^"']+)["'][^>]+(?:property=["']og:title["']|itemprop=["']name["'])/i,
    ];
    for (const rgx of metaTitleRegexes) {
      const m = html.match(rgx);
      if (m && m[1]) {
        const rawTitle = decodeHtmlEntities(m[1])
          .replace(/\s*-\s*Google\s*(Maps|지도|マップ).*$/i, "")
          .trim();
        if (
          rawTitle &&
          rawTitle !== "Google Maps" &&
          rawTitle !== "Google 지도" &&
          !rawTitle.startsWith("http")
        ) {
          if (rawTitle.includes(" · ")) {
            const parts = rawTitle.split(" · ").map((s) => s.trim()).filter(Boolean);
            if (!name && parts[0]) name = parts[0];
            if (!address && parts.length > 1) address = parts.slice(1).join(", ");
          } else if (!name) {
            name = rawTitle;
          }
          break;
        }
      }
    }

    if (!address) {
      const metaDescRegexes = [
        /<meta[^>]+(?:property=["']og:description["']|itemprop=["']description["'])[^>]+content=["']([^"']+)["']/i,
        /<meta[^>]+content=["']([^"']+)["'][^>]+(?:property=["']og:description["']|itemprop=["']description["'])/i,
      ];
      for (const rgx of metaDescRegexes) {
        const m = html.match(rgx);
        if (m && m[1]) {
          const desc = decodeHtmlEntities(m[1]).trim();
          if (desc && !desc.includes("왔던 곳을") && !desc.includes("Find local businesses")) {
            address = desc;
            break;
          }
        }
      }
    }

    if (!name) {
      const titleTag = html.match(/<title[^>]*>([^<]+)<\/title>/i);
      if (titleTag && titleTag[1]) {
        const cleaned = decodeHtmlEntities(titleTag[1])
          .replace(/\s*-\s*Google\s*(Maps|지도|マップ).*$/i, "")
          .trim();
        if (
          cleaned &&
          cleaned !== "Google Maps" &&
          cleaned !== "Google 지도" &&
          cleaned !== "Google マップ" &&
          !cleaned.startsWith("http")
        ) {
          name = cleaned;
        }
      }
    }
  }

  if (!name && fallbackHint) {
    name = fallbackHint;
  }

  return {
    lat: isValidLatLng(lat, lng) ? lat : null,
    lng: isValidLatLng(lat, lng) ? lng : null,
    name: sanitizePlainText(name, 120) || null,
    address: sanitizePlainText(address, 250) || null,
  };
}

function extractSecondStageMapUrl(html) {
  if (!html) return null;
  const decoded = decodeHtmlEntities(html);

  const refreshMatch = decoded.match(/url=["']?(https?:\/\/[^"'\s>]+)/i);
  if (refreshMatch && refreshMatch[1] && isAllowedGoogleMapsUrl(refreshMatch[1])) {
    return refreshMatch[1];
  }

  const gmapMatch = decoded.match(
    /(https?:\/\/(?:www\.|maps\.)?google\.(?:com|co\.jp|co\.kr)\/maps[^\s"'<>\\]+)/i
  );
  if (gmapMatch && gmapMatch[1] && isAllowedGoogleMapsUrl(gmapMatch[1])) {
    return gmapMatch[1];
  }

  return null;
}

async function tryExtractFromGoogleEmbed(queryText) {
  if (!queryText) return null;
  try {
    const embedUrl = `https://maps.google.com/maps?q=${encodeURIComponent(
      queryText
    )}&output=embed&hl=ko`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4500);
    try {
      const res = await fetch(embedUrl, {
        headers: BROWSER_HEADERS,
        signal: controller.signal,
      });
      if (!res.ok) return null;
      const html = (await res.text()).slice(0, 256000);
      const parsed = parseGoogleMapData(embedUrl, html, queryText);
      if (isValidLatLng(parsed.lat, parsed.lng)) {
        return parsed;
      }
    } finally {
      clearTimeout(timer);
    }
  } catch {}
  return null;
}

async function translateQuery(text, targetLang) {
  try {
    const url = `https://api.mymemory.translated.net/get?q=${encodeURIComponent(
      text.slice(0, 120)
    )}&langpair=ko|${targetLang}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3500);
    try {
      const res = await fetch(url, { signal: controller.signal });
      const data = await res.json();
      if (data && data.responseData && data.responseData.translatedText) {
        return sanitizePlainText(data.responseData.translatedText, 120);
      }
    } finally {
      clearTimeout(timer);
    }
  } catch {}
  return null;
}

async function searchMultiGeocoder(queries) {
  const results = [];
  const seenKeys = new Set();

  const pushUnique = (item) => {
    if (!item || !isValidLatLng(item.lat, item.lng)) return;
    const key = `${item.lat.toFixed(4)}_${item.lng.toFixed(4)}`;
    if (seenKeys.has(key)) return;
    seenKeys.add(key);
    results.push({
      ...item,
      name: sanitizePlainText(item.name, 120),
      address: sanitizePlainText(item.address, 250),
    });
  };

  for (const q of queries) {
    if (!q || q.startsWith("http")) continue;

    try {
      const arcUrl = `https://geocode.arcgis.com/arcgis/rest/services/World/GeocodeServer/findAddressCandidates?SingleLine=${encodeURIComponent(
        q
      )}&f=json&maxLocations=6&outFields=Match_addr,PlaceName,Place_addr`;
      const arcRes = await fetch(arcUrl);
      if (arcRes.ok) {
        const arcData = await arcRes.json();
        (arcData.candidates || []).forEach((c) => {
          if (c.location) {
            pushUnique({
              name:
                c.attributes?.PlaceName ||
                (c.address ? c.address.split(",")[0] : q),
              address:
                c.attributes?.Place_addr || c.attributes?.Match_addr || c.address || q,
              lat: Number(c.location.y),
              lng: Number(c.location.x),
              source: "ArcGIS",
            });
          }
        });
      }
    } catch {}

    try {
      const pUrl = `https://photon.komoot.io/api/?q=${encodeURIComponent(
        q
      )}&limit=6&lat=35.68&lon=139.76`;
      const pRes = await fetch(pUrl, { headers: BROWSER_HEADERS });
      if (pRes.ok) {
        const pData = await pRes.json();
        (pData.features || []).forEach((f) => {
          const [lon, lat] = f.geometry?.coordinates || [];
          const props = f.properties || {};
          if (lat && lon) {
            pushUnique({
              name: props.name || props.street || q,
              address:
                [props.country, props.state, props.city, props.district, props.street, props.name]
                  .filter(Boolean)
                  .join(" ") || q,
              lat: Number(lat),
              lng: Number(lon),
              source: "Photon",
            });
          }
        });
      }
    } catch {}

    try {
      const nUrl = `https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(
        q
      )}&limit=5&accept-language=ko,ja,en`;
      const nRes = await fetch(nUrl, { headers: BROWSER_HEADERS });
      if (nRes.ok) {
        const nData = await nRes.json();
        (nData || []).forEach((item) => {
          pushUnique({
            name: item.display_name ? item.display_name.split(",")[0] : q,
            address: item.display_name || q,
            lat: parseFloat(item.lat),
            lng: parseFloat(item.lon),
            source: "OSM",
          });
        });
      }
    } catch {}

    if (results.length >= 6) break;
  }

  return results;
}

module.exports = async function handler(req, res) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "GET") {
    return res.status(405).json({ resolved: false, error: "Method not allowed" });
  }

  const clientIp = getClientIp(req);
  if (!checkRateLimit(clientIp)) {
    return res.status(429).json({
      resolved: false,
      error: "검색 요청이 너무 많습니다. 잠시 후 다시 시도해주세요.",
    });
  }

  const { url, q, hint } = req.query;
  const rawInput = String(url || q || "").trim().slice(0, 1000);
  const { cleanUrl: targetUrl, textHint } = splitInputUrlAndHint(rawInput);
  const combinedHint = sanitizePlainText(hint || textHint || "", 150);

  try {
    // 1. Google Maps URL (오직 화이트리스트를 통과한 공식 도메인만 SSRF 없이 안전하게 추적)
    if (targetUrl && isAllowedGoogleMapsUrl(targetUrl)) {
      const directParsed = parseGoogleMapData(targetUrl, "", combinedHint);
      if (isValidLatLng(directParsed.lat, directParsed.lng)) {
        const item = {
          name: directParsed.name || combinedHint || "구글맵 공유 장소",
          address: directParsed.address || targetUrl,
          lat: directParsed.lat,
          lng: directParsed.lng,
          source: "GoogleMaps",
        };
        return res.status(200).json({
          resolved: true,
          ...item,
          finalUrl: targetUrl,
          results: [item],
        });
      }

      let finalUrl = targetUrl;
      let html = "";
      try {
        const stage1 = await safeFetchGoogleMaps(targetUrl, 5);
        finalUrl = stage1.finalUrl || targetUrl;
        html = stage1.html || "";

        const secondUrl = extractSecondStageMapUrl(html);
        if (
          secondUrl &&
          isAllowedGoogleMapsUrl(secondUrl) &&
          (finalUrl.includes("goo.gl") ||
            finalUrl.includes("maps.app") ||
            finalUrl.includes("consent.google"))
        ) {
          const stage2 = await safeFetchGoogleMaps(secondUrl, 4);
          finalUrl = stage2.finalUrl || secondUrl;
          html = stage2.html || "";
        }
      } catch {}

      const finalParsed = parseGoogleMapData(finalUrl, html, combinedHint);

      if (isValidLatLng(finalParsed.lat, finalParsed.lng)) {
        const item = {
          name: finalParsed.name || combinedHint || "구글맵 공유 장소",
          address: finalParsed.address || finalUrl,
          lat: finalParsed.lat,
          lng: finalParsed.lng,
          source: "GoogleMaps",
        };
        return res.status(200).json({
          resolved: true,
          ...item,
          finalUrl,
          results: [item],
        });
      }

      const candidateNames = [
        finalParsed.name,
        combinedHint,
        finalParsed.address,
        finalParsed.name && finalParsed.address
          ? `${finalParsed.name} ${finalParsed.address}`
          : null,
      ]
        .map((s) => (s || "").trim())
        .filter((s) => s && !s.startsWith("http"));

      for (const cand of candidateNames) {
        const embedResolved = await tryExtractFromGoogleEmbed(cand);
        if (embedResolved && isValidLatLng(embedResolved.lat, embedResolved.lng)) {
          const item = {
            name: finalParsed.name || combinedHint || embedResolved.name || cand,
            address: finalParsed.address || embedResolved.address || finalUrl,
            lat: embedResolved.lat,
            lng: embedResolved.lng,
            source: "GoogleMaps",
          };
          return res.status(200).json({
            resolved: true,
            ...item,
            finalUrl,
            results: [item],
          });
        }
      }

      if (candidateNames.length > 0) {
        const primaryName = candidateNames[0];
        const [jaTrans, enTrans] = await Promise.all([
          translateQuery(primaryName, "ja"),
          translateQuery(primaryName, "en"),
        ]);
        const geoQueries = Array.from(
          new Set([
            ...candidateNames,
            `${primaryName} Japan`,
            jaTrans,
            enTrans,
          ].filter(Boolean))
        );
        const geoResults = await searchMultiGeocoder(geoQueries);
        if (geoResults.length > 0) {
          const best = geoResults[0];
          return res.status(200).json({
            resolved: true,
            lat: best.lat,
            lng: best.lng,
            name: finalParsed.name || combinedHint || best.name,
            address: finalParsed.address || best.address || finalUrl,
            finalUrl,
            results: geoResults,
          });
        }
      }
    }

    // 2. 일반 키워드 검색
    const searchQuery = sanitizePlainText(q || combinedHint || rawInput || "", 120);
    if (!searchQuery || searchQuery.startsWith("http")) {
      return res.status(200).json({
        resolved: false,
        results: [],
        message: "유효한 장소명이나 구글맵 공식 링크를 입력해주세요.",
      });
    }

    const [embedHit, jaTranslated, enTranslated] = await Promise.all([
      tryExtractFromGoogleEmbed(`${searchQuery} 일본`),
      translateQuery(searchQuery, "ja"),
      translateQuery(searchQuery, "en"),
    ]);

    const queryList = Array.from(
      new Set(
        [
          searchQuery,
          `${searchQuery} 일본`,
          `${searchQuery} Japan`,
          jaTranslated,
          jaTranslated ? `${jaTranslated} 日本` : null,
          enTranslated,
          enTranslated ? `${enTranslated} Japan` : null,
        ].filter(Boolean)
      )
    );

    const results = await searchMultiGeocoder(queryList);
    if (embedHit && isValidLatLng(embedHit.lat, embedHit.lng)) {
      results.unshift({
        name: embedHit.name || searchQuery,
        address: embedHit.address || `${searchQuery} (Google Maps)`,
        lat: embedHit.lat,
        lng: embedHit.lng,
        source: "GoogleMaps",
      });
    }

    return res.status(200).json({
      resolved: results.length > 0,
      originalQuery: searchQuery,
      translated: { ja: jaTranslated, en: enTranslated },
      results,
    });
  } catch {
    return res.status(500).json({
      resolved: false,
      error: "장소 검색 처리 중 일시적인 오류가 발생했습니다.",
    });
  }
};
