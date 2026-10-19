// api/resolve.js (Vercel Serverless Node.js Backend)
export default async function handler(req, res) {
  // CORS 허용
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  const { url, q } = req.query;

  // 구글 URL에서 장소명과 정확한 좌표(!3d, !4d 또는 @lat,lng)를 뽑아내는 함수
  const parseGoogleUrl = (targetUrl, htmlText = "") => {
    let name = null;
    let lat = null;
    let lng = null;

    const decodedUrl = decodeURIComponent(targetUrl);

    // 1) /place/장소명 추출
    const placeMatch = decodedUrl.match(/\/maps\/place\/([^/@?]+)/);
    if (placeMatch && placeMatch[1]) {
      name = placeMatch[1].replace(/\+/g, " ").trim();
    }

    // 2) HTML meta og:title에서 장소명 보완 추출
    if (!name && htmlText) {
      const ogTitle =
        htmlText.match(/property="og:title"\s+content="([^"]+)"/i) ||
        htmlText.match(/content="([^"]+)"\s+property="og:title"/i) ||
        htmlText.match(/<title>([^<]+)<\/title>/i);
      if (ogTitle && ogTitle[1]) {
        const cleanTitle = ogTitle[1]
          .replace(/\s*-\s*Google\s*(Maps|지도).*/i, "")
          .trim();
        if (cleanTitle && cleanTitle !== "Google Maps" && cleanTitle !== "Google 지도") {
          name = cleanTitle;
        }
      }
    }

    // 3) 실제 핀 좌표 (!3d위도!4d경도) 최우선 추출
    const exactMatches = [...decodedUrl.matchAll(/!3d(-?\d+\.\d+)!4d(-?\d+\.\d+)/g)];
    if (exactMatches.length > 0) {
      const last = exactMatches[exactMatches.length - 1];
      lat = parseFloat(last[1]);
      lng = parseFloat(last[2]);
    }

    // 4) !3d!4d가 없으면 @위도,경도 또는 q=위도,경도 추출
    if (lat === null || lng === null) {
      const atMatch =
        decodedUrl.match(/@(-?\d+\.\d+),(-?\d+\.\d+)/) ||
        decodedUrl.match(/[?&](?:q|ll|center)=(-?\d+\.\d+),(-?\d+\.\d+)/);
      if (atMatch) {
        lat = parseFloat(atMatch[1]);
        lng = parseFloat(atMatch[2]);
      }
    }

    // 5) HTML 본문 내부에 숨겨진 좌표 추출 (단축 URL 리다이렉트 대응)
    if ((lat === null || lng === null) && htmlText) {
      const htmlExact = htmlText.match(/!3d(-?\d+\.\d+)!4d(-?\d+\.\d+)/);
      const htmlCenter = htmlText.match(/@(-?\d+\.\d+),(-?\d+\.\d+)/);
      const htmlArray = htmlText.match(/\[null,null,(-?\d+\.\d+),(-?\d+\.\d+)\]/);
      const found = htmlExact || htmlCenter || htmlArray;
      if (found) {
        lat = parseFloat(found[1]);
        lng = parseFloat(found[2]);
      }
    }

    return { name, lat, lng };
  };

  try {
    // =================================================================
    // 기능 1: 구글 맵 링크(단축 URL maps.app.goo.gl 및 일반 링크) 해독
    // =================================================================
    if (url) {
      const response = await fetch(url, {
        method: "GET",
        redirect: "follow",
        headers: {
          "User-Agent":
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
          "Accept-Language": "ko-KR,ko;q=0.9,ja;q=0.8,en;q=0.7"
        }
      });

      const finalUrl = response.url || url;
      const html = await response.text();
      const parsed = parseGoogleUrl(finalUrl, html);

      // 만약 URL에서 검색어(q=...)만 있고 좌표가 없다면 아래 검색 엔진으로 연결
      if (parsed.lat !== null && parsed.lng !== null) {
        return res.status(200).json({
          success: true,
          results: [
            {
              name: parsed.name || "구글 지도 공유 장소",
              address: `구글 지도 링크 위치 (${parsed.lat.toFixed(5)}, ${parsed.lng.toFixed(5)})`,
              lat: parsed.lat,
              lng: parsed.lng,
              source: "Google Maps Link"
            }
          ]
        });
      }
    }

    // =================================================================
    // 기능 2: 한글 / 일본어 / 영어 통합 장소 검색 목록 반환
    // =================================================================
    const searchQuery = q || url;
    if (!searchQuery) {
      return res.status(400).json({ error: "검색어(q) 또는 링크(url)가 필요합니다." });
    }

    // 1) 검색어를 일본어(ja)와 영어(en)로 자동 번역 (한국어 호텔명 검색 완벽 대응)
    const translateText = async (text, targetLang) => {
      try {
        const tUrl = `https://translate.googleapis.com/translate_a/single?client=gtx&sl=auto&tl=${targetLang}&dt=t&q=${encodeURIComponent(
          text
        )}`;
        const r = await fetch(tUrl);
        const d = await r.json();
        return d?.[0]?.map((item) => item[0]).join("") || text;
      } catch {
        return text;
      }
    };

    const [jaQuery, enQuery] = await Promise.all([
      translateText(searchQuery, "ja"),
      translateText(searchQuery, "en")
    ]);

    const queriesToRun = Array.from(new Set([searchQuery, jaQuery, enQuery].filter(Boolean)));
    const combinedResults = [];

    // 2) ArcGIS 글로벌 POI 검색 + OpenStreetMap 다국어 검색 병렬 실행
    await Promise.all(
      queriesToRun.map(async (kw) => {
        // ArcGIS World Geocoder
        try {
          const arcUrl = `https://geocode.arcgis.com/arcgis/rest/services/World/GeocodeServer/findAddressCandidates?SingleLine=${encodeURIComponent(
            kw
          )}&f=json&outFields=PlaceName,Place_addr,Match_addr,Type&maxLocations=5`;
          const arcRes = await fetch(arcUrl);
          const arcData = await arcRes.json();
          if (arcData?.candidates) {
            arcData.candidates.forEach((c) => {
              if (c.location) {
                combinedResults.push({
                  name: c.attributes?.PlaceName || c.address.split(",")[0] || kw,
                  address: c.attributes?.Place_addr || c.attributes?.Match_addr || c.address,
                  lat: c.location.y,
                  lng: c.location.x,
                  score: c.score || 80
                });
              }
            });
          }
        } catch (e) {}

        // OpenStreetMap Nominatim
        try {
          const nomUrl = `https://nominatim.openstreetmap.org/search?format=json& addressdetails=1&q=${encodeURIComponent(
            kw
          )}&limit=5&accept-language=ko,ja,en`;
          const nomRes = await fetch(nomUrl, {
            headers: { "User-Agent": "JapanTravelPlannerApp/1.0" }
          });
          const nomData = await nomRes.json();
          if (Array.isArray(nomData)) {
            nomData.forEach((item) => {
              combinedResults.push({
                name: item.name || item.display_name.split(",")[0],
                address: item.display_name,
                lat: parseFloat(item.lat),
                lng: parseFloat(item.lon),
                score: 90
              });
            });
          }
        } catch (e) {}
      })
    );

    // 3) 중복 좌표 제거 및 정렬
    const uniqueResults = [];
    for (const item of combinedResults) {
      const isDup = uniqueResults.some(
        (u) => Math.abs(u.lat - item.lat) < 0.0008 && Math.abs(u.lng - item.lng) < 0.0008
      );
      if (!isDup && !isNaN(item.lat) && !isNaN(item.lng)) {
        uniqueResults.push(item);
      }
    }

    return res.status(200).json({
      success: true,
      translated: { original: searchQuery, ja: jaQuery, en: enQuery },
      results: uniqueResults.slice(0, 8)
    });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
}
