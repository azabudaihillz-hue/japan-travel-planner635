// api/sync.js (맥북 <-> 내 폰 <-> 여자친구 폰 실시간 클라우드 동기화 서버)
module.exports = async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  // GitHub 저장소를 무료 실시간 클라우드 DB로 활용 (환경변수 또는 기본 토큰 사용)
  const GITHUB_TOKEN = process.env.GITHUB_TOKEN || "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";
  const REPO_OWNER = "azabudaihillz-hue";
  const REPO_NAME = "japan-travel-planner635";
  const FILE_PATH = "trip-data.json";
  const apiUrl = `https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/contents/${FILE_PATH}`;

  const headers = {
    Authorization: `token ${GITHUB_TOKEN}`,
    Accept: "application/vnd.github.v3+json",
    "User-Agent": "SmartTravelPlanner-CloudSync"
  };

  try {
    // 1. [GET] 클라우드에 저장된 최신 여행 데이터 불러오기
    if (req.method === "GET") {
      const getRes = await fetch(`${apiUrl}?t=${Date.now()}`, { headers });

      if (getRes.status === 404) {
        return res.status(200).json({ exists: false, data: null });
      }

      if (!getRes.ok) {
        const errText = await getRes.text();
        return res.status(200).json({ exists: false, data: null, warning: errText });
      }

      const fileJson = await getRes.json();
      const contentStr = Buffer.from(fileJson.content, "base64").toString("utf8");
      const parsedData = JSON.parse(contentStr);

      return res.status(200).json({
        exists: true,
        sha: fileJson.sha,
        data: parsedData
      });
    }

    // 2. [POST] 변경된 여행 코스·예산·대형 메모장 내용을 클라우드에 즉시 저장하기
    if (req.method === "POST") {
      const bodyData = typeof req.body === "string" ? JSON.parse(req.body) : req.body;

      // 기존 파일 SHA 조회
      let currentSha = undefined;
      const checkRes = await fetch(`${apiUrl}?t=${Date.now()}`, { headers });
      if (checkRes.ok) {
        const checkJson = await checkRes.json();
        currentSha = checkJson.sha;
      }

      const payloadToSave = {
        ...bodyData,
        updatedAt: new Date().toISOString()
      };

      const encodedContent = Buffer.from(JSON.stringify(payloadToSave, null, 2), "utf8").toString("base64");

      const putBody = {
        message: "cloud-sync: 실시간 여행 계획 및 메모 동기화",
        content: encodedContent
      };
      if (currentSha) {
        putBody.sha = currentSha;
      }

      const putRes = await fetch(apiUrl, {
        method: "PUT",
        headers: {
          ...headers,
          "Content-Type": "application/json"
        },
        body: JSON.stringify(putBody)
      });

      if (!putRes.ok) {
        const putErr = await putRes.text();
        return res.status(500).json({ success: false, error: putErr });
      }

      return res.status(200).json({
        success: true,
        updatedAt: payloadToSave.updatedAt
      });
    }

    return res.status(405).json({ error: "Method not allowed" });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
};
