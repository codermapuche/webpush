const https  = require('https'),
			crypto = require('crypto'),
			url 	 = require('url');

// ------------------------------------------------------------------------

const CONTENT_ENCODING = "aes128gcm",
			AES_GCM = 'aes-128-gcm',
			KEY_LENGTH = 16,
			TAG_LENGTH = 16,
			SHA_256_LENGTH = 32,
			NONCE_LENGTH = 12;

// ------------------------------------------------------------------------

function b64url(buff) {
	return buff.toString('base64')
		.replace(/=/g, '')
		.replace(/\+/g, '-')
		.replace(/\//g, '_');
}

function HMAC_hash(key, input) {
	return crypto
		.createHmac('sha256', key)
		.update(input)
		.digest();
}

function HKDF_expand(prk, info, l) {
	var output = Buffer.alloc(0);
	var T = Buffer.alloc(0);
	info = Buffer.from(info, 'ascii');
	var counter = 0;
	var cbuf = Buffer.alloc(1);
	while (output.length < l) {
		cbuf.writeUIntBE(++counter, 0, 1);
		T = HMAC_hash(prk, Buffer.concat([T, info, cbuf]));
		output = Buffer.concat([output, T]);
	}

	return output.slice(0, l);
}

function generateNonce(base, counter) {
	var nonce = Buffer.from(base);
	var m = nonce.readUIntBE(nonce.length - 6, 6);
	var x = ((m ^ counter) & 0xffffff) +
			((((m / 0x1000000) ^ (counter / 0x1000000)) & 0xffffff) * 0x1000000);
	nonce.writeUIntBE(x, nonce.length - 6, 6);
	return nonce;
}

async function push(pub, sub, data) {
	
	data = Buffer.from(JSON.stringify(data));
						
	// ------------------------------------------------------------------------
	
	let curve = crypto.createECDH('prime256v1');		
	curve.generateKeys();
							
	// ------------------------------------------------------------------------
	
	let salt = crypto.randomBytes(KEY_LENGTH),
			params = {
				version		: CONTENT_ENCODING,
				dh				: sub.p256dh,
				salt			: salt,
				authSecret: sub.auth
			},
			header = {
				rs: 4096,
				salt: params.salt,
				dh: Buffer.from(params.dh, 'base64'),
				authSecret: Buffer.from(params.authSecret, 'base64'),
				keyid: curve.getPublicKey()
			};

	let ints = Buffer.alloc(5);
	ints.writeUIntBE(header.rs, 0, 4);
	ints.writeUIntBE(header.keyid.length, 4, 1);
	var cipher = Buffer.concat([ header.salt, ints, header.keyid ]);

	let secret = HKDF_expand(
								HMAC_hash(header.authSecret, curve.computeSecret(header.dh)), 
								Buffer.concat([
									Buffer.from('WebPush: info\0'),
									header.dh,
									curve.getPublicKey()
								]), 
								SHA_256_LENGTH),
			hmac = HMAC_hash(header.salt, secret),
			key = {
				key  : HKDF_expand(hmac, 'Content-Encoding: ' + CONTENT_ENCODING + '\0', KEY_LENGTH),
				nonce: HKDF_expand(hmac, 'Content-Encoding: nonce\0', NONCE_LENGTH)
			};		
	
	var start = 0;
	var overhead = 1 + TAG_LENGTH;

	var counter = 0;
	var last = false;
	while (!last) {
		var end = start + header.rs - overhead;
		last = end >= data.length;
		
		let buffer = data.slice(start, end),
				nonce = generateNonce(key.nonce, counter),
				gcm = crypto.createCipheriv(AES_GCM, key.key, nonce),
				chunks = [],
				padding = Buffer.alloc(1);
				
		padding.fill(0);

		chunks.push(gcm.update(buffer));
		padding.writeUIntBE(last ? 2 : 1, 0, 1);
		chunks.push(gcm.update(padding));

		gcm.final();
		var tag = gcm.getAuthTag();
		if (tag.length !== TAG_LENGTH) {
			throw new Error('invalid tag generated');
		}
		chunks.push(tag);
		
		cipher = Buffer.concat([ cipher, Buffer.concat(chunks) ]);

		start = end;
		counter++;
	}

	// ------------------------------------------------------------------------
	
	let exp = new Date();
	exp.setSeconds(exp.getSeconds() + (12 * 60 * 60));
	exp = Math.floor(exp.getTime() / 1000);
	
	// ------------------------------------------------------------------------
	
	let aud = url.parse(sub.endpoint);
	
	// ------------------------------------------------------------------------
	
	const jwt = {
		signer: crypto.createSign('RSA-SHA256'),
		header: {
			typ: 'JWT',
			alg: 'ES256'
		},
		payload: {
			aud: aud.protocol + '//' + aud.host,
			exp: exp,
			sub: pub.subject
		},
		token: ''
	}
	
	// ------------------------------------------------------------------------
	
	jwt.token += b64url(Buffer.from(JSON.stringify(jwt.header), 'binary'));
	jwt.token += '.' + b64url(Buffer.from(JSON.stringify(jwt.payload)));		
	jwt.signer.update(jwt.token);
	jwt.token += '.' + b64url(jwt.signer.sign(pub.key, 'base64'));
	
	// ------------------------------------------------------------------------
	
	let options = {
					method: 'POST',
					host: aud.host,
					path: aud.path,
					headers: {
						'TTL'							: 1000 * 60,
						'Content-Encoding': CONTENT_ENCODING,
						'Content-Type'		: 'application/octet-stream',
						'Content-Length'	: cipher.length,
						'Authorization'		: 'vapid t=' + jwt.token + ', k=' + pub.cert
					}
				}
	
	// ------------------------------------------------------------------------
	
	return new Promise((res, rej) => {		
		const req = https.request(options, (resp) => {
      if ( resp.statusCode < 200 || resp.statusCode >= 300 ) {
        return rej(resp.statusCode);
      }
			
      const chunks = [];
      resp.on("data", (chunk) => (chunks.push(chunk)));
      resp.on("end", () => (res(Buffer.concat(chunks).toString())));
    });
		
    req.on("error", rej);
		req.write(cipher);
    req.end();
	});
	
	// ------------------------------------------------------------------------
}

// ------------------------------------------------------------------------

function vapid() {
	const curve = crypto.createECDH('prime256v1');
	curve.generateKeys();
	
	let pubKey = curve.getPublicKey(),
			prvKey = curve.getPrivateKey();
	
	return {
		cert : pubKey.toString('base64'),
		key	 : '-----BEGIN EC PRIVATE KEY-----\n' +
					 Buffer.from('30770201010420' + 
						prvKey.toString('hex') +
						'A00A06082A8648CE3D030107A144034200' +
						pubKey.toString('hex'), 'hex')
						.toString('base64') + '\n' +
					 '-----END EC PRIVATE KEY-----'	
	};
}

// ------------------------------------------------------------------------

module.exports = { 
	vapid, 
	push 
}

// ------------------------------------------------------------------------