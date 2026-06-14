import { SignJWT, importPKCS8 } from "jose";

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const objectPath = url.pathname.substring(1);

    if (!objectPath) return new Response("Not Found", { status: 404 });

    const token = await getAccessToken(env);

    const gcsUrl = `https://storage.googleapis.com/${env.GCS_BUCKET_NAME}/${objectPath}`;
    const response = await fetch(gcsUrl, {
      headers: { Authorization: `Bearer ${token}` },
      cf: {
        cacheTtl: 31536000,
        cacheEverything: true,
      },
    });

    return response;
  },
};

async function getAccessToken(env) {
  const now = Math.floor(Date.now() / 1000);
  const jwtHeader = { alg: "RS256", typ: "JWT" };
  const jwtClaim = {
    iss: env.GCS_CLIENT_EMAIL,
    scope: "https://www.googleapis.com/auth/devstorage.read_only",
    aud: "https://oauth2.googleapis.com/token",
    exp: now + 3600,
    iat: now,
  };

  const privateKey = await importPKCS8(env.GCS_PRIVATE_KEY, "RS256");

  const jwt = await new SignJWT(jwtClaim)
    .setProtectedHeader(jwtHeader)
    .sign(privateKey);

  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`,
  });

  const data = await response.json();
  return data.access_token;
}
