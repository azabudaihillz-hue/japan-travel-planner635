/**
 * Vercel Serverless Function: /api/resolve
 *
 * 1) 핸드폰 구글맵 앱 '공유하기 → 링크 복사' (maps.app.goo.gl/?g_st=ic, 텍스트+링크 혼합 문자열 등) 완벽 해석
 * 2) PC / 모바일 단축 링크 2단계 추적 및 Google Maps HTML 메타데이터(og:image staticmap %2C, og:title, APP_INITIALIZATION_STATE 등) 정밀 파싱
 * 3) 한국어 · 일본어 · 영어 다국어 자동 변환 및 글로벌 지오코더(Photon / ArcGIS / Nominatim) 통합 검색
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

/**
 * 입력 문자열에서 URL과 앞뒤 힌트 텍스트(모바일 구글맵 공유 시 붙는 가게 이름/주소)를 분리
 */
function splitInputUrlAndHint(raw) {
  if (!raw || typeof raw !== "string") {
    return { cleanUrl: null, textHint: "" };
  }
  const trimmed = raw.trim();
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

/**
 * URL 문자열 및 HTML 본문에서 위도/경도, 장소명, 주소를 다각도로 추출
 */
function parseGoogleMapData(urlStr, html = "", fallbackHint = "") {
  let lat = null;
  let lng = null;
  let name = null;
  let address = null;

  const decodedUrl = (() => {
    try {
      return decodeURIComponent(urlStr || "");
    } catch (e) {
      return urlStr || "";
    }
  })();

  // Google Consent 리다이렉트 URL인 경우 내부 continue URL 추출
  let effectiveUrl = urlStr || "";
  if (effectiveUrl.includes("consent.google.") && effectiveUrl.includes("continue=")) {
    const contMatch = effectiveUrl.match(/[?&]continue=([^&]+)/i);
    if (contMatch) {
      try {
        effectiveUrl = decodeURIComponent(contMatch[1]);
      } catch (e) {
        effectiveUrl = contMatch[1];
      }
    }
  }

  const combinedSource = `${effectiveUrl}\n${decodedUrl}\n${decodeHtmlEntities(html)}`;
  let decodedSource = combinedSource;
  try {
    decodedSource =combinedSource.replace(/%2C/gi, ",").replace(/%3A/gi, ":");
  } catch (e) {
    // ignore
  }

  // 1. 가장 정확한 실제 핀 좌표: !3d위도!4d경도
  const bangMatch = decodedSource.match(/!3d(-?\d+\.\d+)!4d(-?\d+\.\d+)/);
  if (bangMatch) {
    const cLat = parseFloat(bangMatch[1]);
    const cLng = parseFloat(bangMatch[2]);
    if (isValidLatLng(cLat, cLng)) {
      lat = cLat;
      lng = cLng;
    }
  }

  // 2. og:image 등의 staticmap?center=위도,경도 (%2C 인코딩 포함)
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

  // 3. URL 경로의 /@위도,경도
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

  // 4. 쿼리 파라미터 q=위도,경도 / query=위도,경도 / ll=위도,경도 / daddr=위도,경도
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

  // 5. Google Maps 내부 JSON 배열 [null,null,위도,경도]
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

  // 6. Google Maps APP_INITIALIZATION_STATE의 [거리, 경도(122~154), 위도(24~46)] 패턴
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

  // --- 장소명(name) 및 주소(address) 추출 ---
  // A. URL의 /maps/place/장소명 또는 /maps/search/장소명
  const placeMatch = effectiveUrl.match(/\/maps\/(?:place|search)\/([^/@?&]+)/i);
  if (placeMatch && placeMatch[1]) {
    try {
      const candidate = decodeURIComponent(placeMatch[1].replace(/\+/g, " ")).trim();
      if (candidate && !/^(-?\d+\.\d+),(-?\d+\.\d+)$/.test(candidate)) {
        name = candidate;
      }
    } catch (e) {
      // ignore
    }
  }

  // B. URL 쿼리 파라미터 ?q=장소명 또는 ?query=장소명
  if (!name) {
    const qNameMatch = effectiveUrl.match(/[?&](?:q|query)=([^&]+)/i);
    if (qNameMatch && qNameMatch[1]) {
      try {
        const candidate = decodeURIComponent(qNameMatch[1].replace(/\+/g, " ")).trim();
        if (candidate && !/^(-?\d+\.\d+)[,\s]+(-?\d+\.\d+)$/.test(candidate)) {
          name = candidate;
        }
      } catch (e) {
        // ignore
      }
    }
  }

  // C. HTML <meta property="og:title"> 또는 <meta itemprop="name"> (속성 순서 무관!)
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
          // "가게이름 · 주소" 형태인 경우 분리
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

    // D. HTML <meta property="og:description"> 또는 <meta itemprop="description">
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

    // E. <title>장소명 - Google 지도</title>
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
    name: name || null,
    address: address || null,
  };
}

/**
 * HTML 내부에 2차 이동 URL(meta refresh, window.location, google.com/maps 링크)이 있으면 추출
 */
function extractSecondStageMapUrl(html) {
  if (!html) return null;
  const decoded = decodeHtmlEntities(html);

  // 1) meta http-equiv="refresh" content="0;url=..."
  const refreshMatch = decoded.match(/url=["']?(https?:\/\/[^"'\s>]+)/i);
  if (refreshMatch && refreshMatch[1]) {
    return refreshMatch[1];
  }

  // 2) google.com/maps/place/... 또는 google.com/maps?... 링크
  const gmapMatch = decoded.match(
    /(https?:\/\/(?:www\.|maps\.)?google\.(?:com|co\.jp|co\.kr)\/maps[^\s"'<>\\]+)/i
  );
  if (gmapMatch && gmapMatch[1]) {
    return gmapMatch[1];
  }

  return null;
}

/**
 * Google Maps Embed 페이지를 통해 장소명/ 주소의 좌표를 보조 추출
 */
async function tryExtractFromGoogleEmbed(queryText) {
  if (!queryText) return null;
  try {
    const embedUrl = `https://maps.google.com/maps?q=${encodeURIComponent(
      queryText
    )}&output=embed&hl=ko`;
    const res = await fetch(embedUrl, {
      headers: BROWSER_HEADERS,
    });
    if (!res.ok) return null;
    const html = await res.text();
    const parsed = parseGoogleMapData(embedUrl, html, queryText);
    if (isValidLatLng(parsed.lat, parsed.lng)) {
      return parsed;
    }
  } catch (e) {
    // ignore
  }
  return null;
}

/**
 * 다국어 번역 (한국어 -> 일본어, 영어)
 */
async function translateQuery(text, targetLang) {
  try {
    const url = `https://api.mymemory.translated.net/get?q=${encodeURIComponent(
      text
    )}&langpair=ko|${targetLang}`;
    const res = await fetch(url);
    const data = await res.json();
    if (data && data.responseData && data.responseData.translatedText) {
      return data.responseData.translatedText.trim();
    }
  } catch (e) {
    // ignore
  }
  return null;
}

/**
 * 다중 글로벌 지오코딩 엔진 (Photon + ArcGIS + Nominatim)
 */
async function searchMultiGeocoder(queries) {
  const results = [];
  const seenKeys = new Set();

  const pushUnique = (item) => {
    if (!item || !isValidLatLng(item.lat, item.lng)) return;
    const key = `${item.lat.toFixed(4)}_${item.lng.toFixed(4)}`;
    if (seenKeys.has(key)) return;
    seenKeys.add(key);
    results.push(item);
  };

  for (const q of queries) {
    if (!q || q.startsWith("http")) continue;

    // 1. ArcGIS World Geocoder (한국어/일본어/영어 상호명 및 주소 검색에 매우 강력)
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
    } catch (e) {}

    // 2. Photon (Komoot) OpenStreetMap 검색
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
    } catch (e) {}

    // 3. OpenStreetMap Nominatim
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
    } catch (e) {}

    if (results.length >= 6) break;
  }

  return results;
}

module.exports = async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  const { url, q, hint } = req.query;
  const rawInput = (url || q || "").trim();
  const { cleanUrl: targetUrl, textHint } = splitInputUrlAndHint(rawInput);
  const combinedHint = (hint || textHint || "").trim();

  try {
    // 1. Google Maps URL (모바일 단축 링크 maps.app.goo.gl / goo.gl / google.com/maps 등) 해석
    if (
      targetUrl &&
      (targetUrl.includes("google.") ||
        targetUrl.includes("goo.gl") ||
        targetUrl.includes("maps.app"))
    ) {
      // 1-A. 입력된 URL 자체에 이미 좌표가 있는지 확인
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

      // 1-B. 서버에서 단축 URL 리다이렉트 추적 (1단계 + 2단계)
      let finalUrl = targetUrl;
      let html = "";
      try {
        const response = await fetch(targetUrl, {
          method: "GET",
          redirect: "follow",
          headers: BROWSER_HEADERS,
        });
        finalUrl = response.url || targetUrl;
        html = await response.text();

        // 만약 여전히 단축 도메인이거나 HTML 내에 2차 구글맵 URL이 숨어 있다면 한 번 더 추적
        const secondUrl = extractSecondStageMapUrl(html);
        if (
          secondUrl &&
          (finalUrl.includes("goo.gl") ||
            finalUrl.includes("maps.app") ||
            finalUrl.includes("consent.google"))
        ) {
          const response2 = await fetch(secondUrl, {
            method: "GET",
            redirect: "follow",
            headers: BROWSER_HEADERS,
          });
          finalUrl = response2.url || secondUrl;
          html = await response2.text();
        }
      } catch (fetchErr) {
        // 네트워크 에러 시 아래 지오코딩 폴백으로 진행
      }

      const finalParsed = parseGoogleMapData(finalUrl, html, combinedHint);

      // 좌표가 바로 추출된 경우 즉시 반환!
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

      // 1-C. 모바일 공유 링크가 좌표 없이 장소명/주소만 포함한 URL(/maps/place/장소명/data=!4m2...)로 리다이렉트된 경우!
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

      // Google Embed 페이지에서 좌표 추출 시도
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

      // 지오코더(ArcGIS / Photon / Nominatim + 다국어 번역)로 추출된 장소명 검색! (절대 원본 단축 URL을 검색하지 않음)
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

    // 2. 일반 키워드 검색 (한국어 / 일본어 / 영어 다국어 자동 검색)
    const searchQuery = (q || combinedHint || rawInput || "").trim();
    if (!searchQuery || searchQuery.startsWith("http")) {
      return res.status(200).json({
        resolved: false,
        results: [],
        message: "유효한 장소명이나 좌표를 찾지 못했습니다.",
      });
    }

    // Google Embed에서도 1순위 좌표 후보 확인
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
  } catch (err) {
    return res.status(500).json({
      resolved: false,
      error: err.message,
    });
  }
};
