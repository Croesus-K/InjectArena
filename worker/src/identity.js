'use strict';
/**
 * arena-worker —— HMAC-SHA256 签名工具（WebCrypto，Workers 与 Node ≥22 通用）。
 *
 * 一把钥匙三处用（同一个 ARENA_SESSION_SECRET）：
 *   1. GitHub 会话 Cookie（30 天）
 *   2. 破阵凭证（2 小时，防伪造上榜——灌水上限 = 真实破阵）
 *   3. OAuth state（10 分钟，防 CSRF）
 *
 * 签名格式：<base64url(JSON payload)>.<base64url(HMAC)>；验证常量时间比较。
 */

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function b64urlFromBytes(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function bytesFromB64url(str) {
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (str.length % 4)) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function hmacKey(secret) {
  return crypto.subtle.importKey('raw', encoder.encode(String(secret)), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
}

async function hmacSignB64url(secret, message) {
  const sig = await crypto.subtle.sign('HMAC', await hmacKey(secret), encoder.encode(message));
  return b64urlFromBytes(new Uint8Array(sig));
}

/** 生成随机 base64url 串（OAuth nonce 等场景）。 */
export function randomToken(bytes = 16) {
  const b = new Uint8Array(bytes);
  crypto.getRandomValues(b);
  return b64urlFromBytes(b);
}

/**
 * 签发带过期时间的令牌。
 * @param {string} secret ARENA_SESSION_SECRET
 * @param {object} payload 进入签名的业务字段（会自动附加 exp）
 * @param {number} ttlMs 有效毫秒数
 * @returns {Promise<string>} token
 */
export async function signToken(secret, payload, ttlMs, now) {
  const t = now === undefined ? Date.now() : now;
  const body = { ...payload, exp: t + ttlMs };
  const payloadB64 = b64urlFromBytes(encoder.encode(JSON.stringify(body)));
  const sig = await hmacSignB64url(secret, payloadB64);
  return payloadB64 + '.' + sig;
}

/**
 * 校验令牌：签名不符 / 解析失败 / 过期一律返回 null（不区分原因，防侧信道）。
 * @returns {Promise<object|null>}
 */
export async function verifyToken(secret, token, now) {
  const t = now === undefined ? Date.now() : now;
  if (typeof token !== 'string') return null;
  const dot = token.indexOf('.');
  if (dot <= 0) return null;
  const payloadB64 = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  if (!payloadB64 || !sig) return null;
  const expected = await hmacSignB64url(secret, payloadB64);
  if (!timingSafeEqual(sig, expected)) return null;
  let payload;
  try {
    payload = JSON.parse(decoder.decode(bytesFromB64url(payloadB64)));
  } catch (_) {
    return null;
  }
  if (!payload || typeof payload !== 'object' || typeof payload.exp !== 'number' || payload.exp < t) return null;
  return payload;
}

function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
