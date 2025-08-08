// functions/presign.js

export async function onRequestGet(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const key = url.searchParams.get('key');

  if (!key) {
    return new Response('Missing key', { status: 400 });
  }

  const accessKey = env.R2_ACCESS_KEY;
  const secretKey = env.R2_SECRET_KEY;
  const region = 'auto';
  const service = 's3';
  const bucket = env.R2_BUCKET;
  const endpoint = env.R2_ENDPOINT;
  const method = 'GET';
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '') + 'Z';
  const dateStamp = now.toISOString().slice(0, 10).replace(/-/g, '');
  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;

  const host = new URL(endpoint).host;
  const canonicalUri = `/${bucket}/${key}`;
  const canonicalQueryString = '';
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

  const encoder = new TextEncoder();
  const cryptoKey = await crypto.subtle.digest(
    'SHA-256',
    encoder.encode(canonicalRequest)
  );
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    credentialScope,
    [...new Uint8Array(cryptoKey)].map(b => b.toString(16).padStart(2, '0')).join('')
  ].join('\n');

  const signingKey = await getSigningKey(secretKey, dateStamp, region, service);
  const signature = await hmacSha256(signingKey, stringToSign);
  const signatureHex = [...new Uint8Array(signature)].map(b => b.toString(16).padStart(2, '0')).join('');

  const presignedUrl = `${endpoint}/${bucket}/${key}` +
    `?X-Amz-Algorithm=AWS4-HMAC-SHA256` +
    `&X-Amz-Credential=${encodeURIComponent(accessKey + '/' + credentialScope)}` +
    `&X-Amz-Date=${amzDate}` +
    `&X-Amz-Expires=300` +
    `&X-Amz-SignedHeaders=host` +
    `&X-Amz-Signature=${signatureHex}`;

  return new Response(JSON.stringify({ url: presignedUrl }), {
    headers: { 'Content-Type': 'application/json' }
  });
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