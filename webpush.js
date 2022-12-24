const https  = require('https'),
      crypto = require('crypto'),
      url    = require('url');

// ------------------------------------------------------------------------
// https://datatracker.ietf.org/doc/html/rfc5869
// ------------------------------------------------------------------------

function HKDF_expand(prk, info, l) {
  let output = Buffer.alloc(0),
      T = Buffer.alloc(0),
      counter = 0,
      cbuf = Buffer.alloc(1);

  info = Buffer.from(info, 'ascii');

  while (output.length < l) {
    cbuf.writeUIntBE(++counter, 0, 1);
    T = HMAC_hash(prk, Buffer.concat([T, info, cbuf]));
    output = Buffer.concat([output, T]);
  }

  return output.slice(0, l);
}

function HMAC_hash(key, input) {
  return crypto
    .createHmac('sha256', key)
    .update(input)
    .digest();
}

// ------------------------------------------------------------------------
// https://datatracker.ietf.org/doc/html/rfc5869#section-2.2
// ------------------------------------------------------------------------

function HKDF_extract(key, input) {
  return HMAC_hash(key, input);
}

// ------------------------------------------------------------------------
// https://datatracker.ietf.org/doc/html/rfc7515#appendix-C
// ------------------------------------------------------------------------

function base64urlEncode(str) {
  return base64urlEscape(Buffer.from(str).toString('base64'));
}

function base64urlEscape(str) {
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// ------------------------------------------------------------------------
// https://datatracker.ietf.org/doc/html/rfc8292
// ------------------------------------------------------------------------

function VAPID_generateKeys() {
  const curve = crypto.createECDH('prime256v1');
  curve.generateKeys();

  let privateKey = curve.getPrivateKey(),
      publicKey  = curve.getPublicKey();

  return {
    cert  : base64urlEncode(publicKey),
    key   : JSON.stringify({
              key: {
                kty : 'EC',
                crv : 'P-256',
                x   : base64urlEncode(publicKey.slice(1, 33)),
                y   : base64urlEncode(publicKey.slice(33, 65)),
                d   : base64urlEncode(privateKey)
              },
              format: 'jwk'
            })
  };
}

// ------------------------------------------------------------------------
// https://datatracker.ietf.org/doc/html/rfc7518#section-3.4
// ------------------------------------------------------------------------

function VAPID_jwt(key, audience, subject, expire) {
  const curr = new Date(),
        offs = curr.getTimezoneOffset(),
        header = {
          typ: 'JWT',
          alg: 'ES256'
        },
        payload = {
          aud: audience.protocol + '//' + audience.host,
          exp: Math.floor((Date.now() - offs) / 1000) + expire,
          sub: subject
        };

  return JWT_create(key, header, payload);
}

// ------------------------------------------------------------------------
// https://datatracker.ietf.org/doc/html/rfc8292#section-2.4
// ------------------------------------------------------------------------

function VAPID_request(endpoint, cipher, jwt, cert) {
  
  const options = {
    method: 'POST',
    host: endpoint.host,
    path: endpoint.path,
    headers: {
      'TTL'             : 1000 * 60,
      'Content-Encoding': 'aes128gcm',
      'Content-Type'    : 'application/octet-stream',
      'Content-Length'  : cipher.length,
      'Authorization'   : 'vapid t=' + jwt + ', k=' + cert
    }
  };

  // ------------------------------------------------------------------------

  return new Promise((res, rej) => {
    const req = https.request(options, (resp) => {
      const chunks = [];
      resp.on("data", (chunk) => (chunks.push(chunk)));
      resp.on("end", () => {
        const body = Buffer.concat(chunks).toString();

        if ( resp.statusCode < 200 || resp.statusCode >= 300 ) {
          return rej({ body,
            statusCode: resp.statusCode
          });
        }

        res(body);
      });
    });

    req.on("error", rej);
    req.write(cipher);
    req.end();
  });
}

// ------------------------------------------------------------------------
// https://datatracker.ietf.org/doc/html/rfc7519
// ------------------------------------------------------------------------

function JWT_create(key, header, payload) {
  header  = JSON.stringify(header);
  payload = JSON.stringify(payload);

  header  = Buffer.from(header);
  payload = Buffer.from(payload);

  header  = base64urlEncode(header);
  payload = base64urlEncode(payload);

  let sign = JWS_sign(header, payload, key);
  sign = base64urlEncode(sign);

  return header + '.' + payload + '.' + sign;
}

// ------------------------------------------------------------------------
// https://datatracker.ietf.org/doc/html/rfc7515
// ------------------------------------------------------------------------

function JWS_sign(header, payload, privateKey) {
  return crypto.sign("SHA256", header + '.' + payload, privateKey);
}

// ------------------------------------------------------------------------
// https://datatracker.ietf.org/doc/html/rfc4086
// ------------------------------------------------------------------------

function RANDOM_salt(length) {
  return crypto.randomBytes(length);
}

// ------------------------------------------------------------------------
// SECG, "SEC 1: Elliptic Curve Cryptography", Version 2.0,
// May 2009, <http://www.secg.org/>.
// ------------------------------------------------------------------------

function ECDH(c_private, c_public) {
  return c_private.computeSecret(c_public);
}

// ------------------------------------------------------------------------
// https://datatracker.ietf.org/doc/html/rfc8188#section-2.3
// ------------------------------------------------------------------------

function generateNonce(base, counter) {
  var nonce = Buffer.from(base);
  var m = nonce.readUIntBE(nonce.length - 6, 6);
  var x = ((m ^ counter) & 0xffffff) +
      ((((m / 0x1000000) ^ (counter / 0x1000000)) & 0xffffff) * 0x1000000);
  nonce.writeUIntBE(x, nonce.length - 6, 6);
  return nonce;
}

// ------------------------------------------------------------------------
// https://datatracker.ietf.org/doc/html/rfc8291#section-4
// ------------------------------------------------------------------------

const RECORD_SIZE = 4096,
      AES_GCM     = 'aes-128-gcm',
      OVERHEAD    = 16 + 1;

// ------------------------------------------------------------------------

function push(pub, sub, data) {

  data = Buffer.from(JSON.stringify(data));

  if (RECORD_SIZE - OVERHEAD <= data.length) {
    throw "Max data size of push is: " + (RECORD_SIZE - OVERHEAD);
  }

  // ------------------------------------------------------------------------
  // https://datatracker.ietf.org/doc/html/rfc8291#section-2
  // ------------------------------------------------------------------------

  let curve = crypto.createECDH('prime256v1'),
      salt = RANDOM_salt(16),
      keyid;

  curve.generateKeys();
  keyid = curve.getPublicKey();

  // ------------------------------------------------------------------------
  // https://datatracker.ietf.org/doc/html/rfc8291#section-3.4
  // ------------------------------------------------------------------------

  let ua_public   = Buffer.from(sub.p256dh, 'base64'),
      ecdh_secret = ECDH(curve, ua_public),
      auth_secret = Buffer.from(sub.auth, 'base64'),
      PRK_key     = HKDF_extract(auth_secret, ecdh_secret),
      key_str     = Buffer.from('WebPush: info\0'),
      key_info    = Buffer.concat([ key_str, ua_public, keyid ]),
      IKM         = HKDF_expand(PRK_key, key_info, 32),
      PRK         = HKDF_extract(salt, IKM),
      cek_info    = Buffer.from('Content-Encoding: aes128gcm\0'),
      CEK         = HKDF_expand(PRK, cek_info, 16),
      nonce_info  = Buffer.from('Content-Encoding: nonce\0'),
      NONCE       = HKDF_expand(PRK, nonce_info, 12);

  // ------------------------------------------------------------------------
  // https://datatracker.ietf.org/doc/html/rfc8188#section-2.1
  // ------------------------------------------------------------------------

  let ecch = Buffer.alloc(5);
  ecch.writeUIntBE(RECORD_SIZE, 0, 4);
  ecch.writeUIntBE(keyid.length, 4, 1);
  ecch = Buffer.concat([ salt, ecch, keyid ]);

  // ------------------------------------------------------------------------
  // https://datatracker.ietf.org/doc/html/rfc8291#appendix-A
  // ------------------------------------------------------------------------

  let nonce  = generateNonce(NONCE, 0),
      cipher = crypto.createCipheriv(AES_GCM, CEK, nonce);

  data = Buffer.concat([ data, Buffer.from([ 2 ]) ]);
  data = cipher.update(data);
  cipher.final();

  // ------------------------------------------------------------------------
  // https://datatracker.ietf.org/doc/html/rfc5349.html#section-7
  // ------------------------------------------------------------------------
  
  let privateKey = JSON.parse(JSON.stringify(pub.key)); 
  privateKey.dsaEncoding = 'ieee-p1363';
  
  // ------------------------------------------------------------------------

  const endpoint = url.parse(sub.endpoint),
        jwt = VAPID_jwt(privateKey, endpoint, pub.subject, 12 * 60 * 60);

  cipher = Buffer.concat([ ecch, data, cipher.getAuthTag() ]);

  // ------------------------------------------------------------------------

  return VAPID_request(endpoint, cipher, jwt, pub.cert);
}

// --------------------------------------------------------------------------

module.exports = {
  VAPID_generateKeys,
  push
}

// --------------------------------------------------------------------------
