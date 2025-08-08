export async function onRequestGet(context) {
  const { request, env } = context;

  // No key parameter is required for listing objects
  try {
    const accessKey = env.R2_ACCESS_KEY;
    const secretKey = env.R2_SECRET_KEY;
    const bucket = env.R2_BUCKET;
    const endpoint = env.R2_ENDPOINT;
    const region = 'auto';

    const method = 'GET';
    const host = new URL(endpoint).host;
    const amzDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '') + 'Z';
    const dateStamp = amzDate.slice(0, 8);
    const credentialScope = `${dateStamp}/${region}/s3/aws4_request`;

    const canonicalUri = `/${bucket}`;
    const canonicalQueryString = `list-type=2&prefix=${encodeURIComponent('Web/')}`;
    const canonicalHeaders = `host:${host}\n`;
    const signedHeaders = 'host';
    const payloadHash = 'UNSIGNED-PAYLOAD';

    const canonicalRequest = [
      method,
      canonicalUri,
      canonicalQueryString,
      canonicalHeaders,
      signedHeaders,
      payloadHash
    ].join('\n');

    console.log("Canonical request:", canonicalRequest);  // Log canonical request

    const encoder = new TextEncoder();
    const hash = await crypto.subtle.digest('SHA-256', encoder.encode(canonicalRequest));
    const stringToSign = [
      'AWS4-HMAC-SHA256',
      amzDate,
      credentialScope,
      [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, '0')).join('')
    ].join('\n');

    console.log("String to sign:", stringToSign);  // Log string to sign

    const signingKey = await getSigningKey(secretKey, dateStamp, region, 's3');
    const signature = await hmacSha256(signingKey, stringToSign);
    const signatureHex = [...new Uint8Array(signature)].map(b => b.toString(16).padStart(2, '0')).join('');

    console.log("Generated signature:", signatureHex);  // Log signature

    const authHeader = `AWS4-HMAC-SHA256 Credential=${accessKey}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signatureHex}`;

    const fetchUrl = `${endpoint}/${bucket}?${canonicalQueryString}`;
    console.log("Requesting R2 URL:", fetchUrl); // Log the final URL

    const r2Response = await fetch(fetchUrl, {
      method: 'GET',
      headers: {
        'Authorization': authHeader,
        'X-Amz-Date': amzDate,
        'X-Amz-Content-Sha256': payloadHash
      }
    });

    console.log("R2 Response status:", r2Response.status);

    if (!r2Response.ok) {
      const errorText = await r2Response.text();
      console.log("Error fetching from R2:", errorText); // Log R2's error message
      return new Response(`Failed to list objects: ${r2Response.status} - ${errorText}`, { status: 500 });
    }

    const xml = await r2Response.text();
    return new Response(xml, {
      headers: { 'Content-Type': 'application/xml' }
    });

  } catch (error) {
    console.error("Error in list function:", error);
    return new Response('Internal Server Error: ' + error.message, { status: 500 });
  }
}

async function getSigningKey(secretKey, dateStamp, region, service) {
  const kDate = await hmacSha256(`AWS4${secretKey}`, dateStamp);
  const kRegion = await hmacSha256(kDate, region);
  const kService = await hmacSha256(kRegion, service);
  return await hmacSha256(kService, 'aws4_request');
}

async function hmacSha256(key, msg) {
  const keyBytes = typeof key === 'string' ? new TextEncoder().encode(key) : key;
  const cryptoKey = await crypto.subtle.importKey(
    'raw', keyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false, ['sign']
  );
  return await crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(msg));
}
