// api/resolve.js (Vercel Serverless Node.js - CommonJS 호환 무적 버전)
module.exports = async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  const { url, q } = req.query || {};

  // 구글 URL에서 장소명과 정확한 좌표(!3d, !4d 또는 @lat,lng) 추출
  const parseGoogleUrl = (targetUrl, htmlText = "") => {
    let name = null;
    let lat = null;
    let lng = null;

    let decodedUrl = targetUrl;
    try {
      decodedUrl = decodeURIComponent(targetUrl);
    } catch (e) {}

    // 1) /place/장소명 추출
    const placeMatch = decodedUrl.match(/\/maps\/place\/([^/@?]+)/);
    if (placeMatch && placeMatch[1]) {
      name = placeMatch[1].replace(/\+/g, " ").trim();
    }

    // 2) search/?q=장소명 추출
    const searchMatch = decodedUrl.match(/[?&](?:q|query)=([^&]+)/);
    if (!name && searchMatch && searchMatch[1]) {
      name = searchMatch[1].replace(/\+/g, " ").trim();
    }

    // 3) HTML meta og:title에서 장소명 추출
    if (!name && htmlText) {
      const ogTitle =
        htmlText.match(/property="og:title"\s+content="([^"]+)"/i) ||
        htmlText.match(/content="([^"]+)"\s+property="og:title"/i) ||
        htmlText.match(/<title>([^<]+)<\/title>/i);
      if (ogTitle && ogTitle[1]) {
        const cleanTitle = ogTitle[1]
          .replace(/\s*-\s*Google\s*(Maps|지도|マップ).*/i, "")
          .trim();
        if (cleanTitle && !cleanTitle.includes("Google")) {
          name = cleanTitle;
        }
      }
    }

    // 4) 실제 핀 좌표 (!3d위도!4d경도) 최우선 추출
    const exactMatches = [...decodedUrl.matchAll(/!3d(-?\d+\.\d+)!4d(-?\d+\.\d+)/g)];
    if (exactMatches.length > 0) {
      const last = exactMatches[exactMatches.length - 1];
      lat = parseFloat(last[1]);
      lng = parseFloat(last[2]);
    }

    // 5) @위도,경도 추출
    if (lat === null || lng === null) {
      const atMatch =
        decodedUrl.match(/@(-?\d+\.\d+),(-?\d+\.\d+)/) ||
        decodedUrl.match(/(-?\d+\.\d+)\s*,\s*(-?\d+\.\d+)/);
      if (atMatch) {
        lat = parseFloat(atMatch[1]);
        lng = parseFloat(atMatch[2]);
      }
    }

    // 6) HTML 본문 내 숨겨진 좌표 추출 (maps.app.goo.gl 단축링크 대응)
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
    // 1. 구글 맵 링크 해독
    if (url) {
      const directTry = parseGoogleUrl(url);
      let finalParsed = directTry;

      if (directTry.lat === null || directTry.lng === null || !directTry.name) {
        try {
          const response = await fetch(url, {
            method: "GET",
            redirect: "follow",
            headers: {
              "User-Agent":
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
              "Accept-Language": "ko-KR,ko;q=0.9,ja;q=0.8,en;q=0.7"
            }
          });
          const finalUrl = response.url || url;
          const html = await response.text();
          finalParsed = parseGoogleUrl(finalUrl, html);
        } catch (fetchErr) {}
      }

      if (finalParsed.lat !== null && finalParsed.lng !== null) {
        return res.status(200).json({
          success: true,
          results: [
            {
              name: finalParsed.name || "구글 지도 공유 위치",
              address: `구글 지도 정확한 핀 위치 (${finalParsed.lat.toFixed(5)}, ${finalParsed.lng.toFixed(5)})`,
              lat: finalParsed.lat,
              lng: finalParsed.lng
            }
          ]
        });
      }
    }

    // 2. 한글 / 일본어 / 영어 다국어 장소 검색
    const searchQuery = (q || url || "").trim();
    if (!searchQuery) {
      return res.status(400).json({ error: "검색어가 비어 있습니다." });
    }

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

    // 어순 변경 키워드 추가 (예: "호텔 아마넥" <-> "Amanek Hotel")
    const extraQueries = [];
    if (enQuery.toLowerCase().startsWith("hotel ")) {
      extraQueries.push(enQuery.replace(/^hotel\s+/i, "") + " Hotel");
    }

    const queriesToRun = Array.from(
      new Set([searchQuery, jaQuery, enQuery, ...extraQueries].filter(Boolean))
    );
    const combinedResults = [];

    await Promise.all(
      queriesToRun.map(async (kw) => {
        // 엔진 A: Photon (Komoot) 글로벌 오픈스트리트맵 검색엔진 (호텔·매장 검색률 최고)
        try {
          const pRes = await fetch(
            `https://photon.komoot.io/api/?q=${encodeURIComponent(kw)}&limit=6`
          );
          const pData = await pRes.json();
          if (pData?.features) {
            pData.features.forEach((f) => {
              const coords = f.geometry?.coordinates;
              const props = f.properties || {};
              if (coords && coords.length === 2) {
                const title = props.name || props.street || kw;
                const addrParts = [props.country, props.state, props.city, props.district, props.street]
                  .filter(Boolean)
                  .join(" ");
                combinedResults.push({
                  name: title,
                  address: addrParts || title,
                  lat: parseFloat(coords[1]),
                  lng: parseFloat(coords[0])
                });
              }
            });
          }
        } catch (e) {}

        // 엔진 B: ArcGIS World Geocoder
        try {
          const arcUrl = `https://geocode.arcgis.com/arcgis/rest/services/World/GeocodeServer/findAddressCandidates?SingleLine=${encodeURIComponent(
            kw
          )}&f=json&outFields=PlaceName,Place_addr,Match_addr&maxLocations=6`;
          const arcRes = await fetch(arcUrl);
          const arcData = await arcRes.json();
          if (arcData?.candidates) {
            arcData.candidates.forEach((c) => {
              if (c.location) {
                combinedResults.push({
                  name: c.attributes?.PlaceName || c.address.split(",")[0] || kw,
                  address: c.attributes?.Place_addr || c.attributes?.Match_addr || c.address,
                  lat: c.location.y,
                  lng: c.location.x
                });
              }
            });
          }
        } catch (e) {}

        // 엔진 C: OpenStreetMap Nominatim
        try {
          const nomUrl = `https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(
            kw
          )}&limit=5&accept-language=ko,ja,en`;
          const nomRes = await fetch(nomUrl, {
            headers: { "User-Agent": "SmartTravelPlanner/2.0" }
          });
          const nomData = await nomRes.json();
          if (Array.isArray(nomData)) {
            nomData.forEach((item) => {
              combinedResults.push({
                name: item.name || item.display_name.split(",")[0],
                address: item.display_name,
                lat: parseFloat(item.lat),
                lng: parseFloat(item.lon)
              });
            });
          }
        } catch (e) {}
      })
    );

    const uniqueResults = [];
    for (const item of combinedResults) {
      const isDup = uniqueResults.some(
        (u) => Math.abs(u.lat - item.lat) < 0.0006 && Math.abs(u.lng - item.lng) < 0.0006
      );
      if (!isDup && !isNaN(item.lat) && !isNaN(item.lng)) {
        uniqueResults.push(item);
      }
    }

    return res.status(200).json({
      success: true,
      translated: { original: searchQuery, ja: jaQuery, en: enQuery },
      results: uniqueResults.slice(0, 10)
    });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
};
