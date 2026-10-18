export default async function handler(req, res) {
  // CORS 헤더 설정 (어디서 호출하든 막히지 않도록 허용)
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  // 클라이언트에서 넘겨준 ?url= 값 추출
  const targetUrl = req.query?.url;
  if (!targetUrl) {
    return res.status(400).json({ error: "Missing url parameter" });
  }

  try {
    // 구글 서버로 직접 리다이렉트(redirect: 'follow')를 따라가 최종 전체 URL과 페이지 본문 가져오기
    const response = await fetch(targetUrl, {
      method: "GET",
      redirect: "follow",
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept-Language": "ko-KR,ko;q=0.9,ja;q=0.8,en-US;q=0.7"
      }
    });

    // 최종 이동된 전체 구글맵 주소 (예: https://www.google.com/maps/place/...!3d34.667!4d135.503...)
    const finalUrl = response.url;
    // 페이지 본문 HTML (og:image 내 정확한 center=위도,경도 메타태그 포함)
    const html = await response.text();

    return res.status(200).json({
      finalUrl,
      html: html.slice(0, 150000) // 좌표 추출에 필요한 앞부분 본문 전달
    });
  } catch (err) {
    return res.status(500).json({
      error: "Failed to resolve redirect",
      details: String(err.message || err)
    });
  }
}