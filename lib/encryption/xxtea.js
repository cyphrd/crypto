var utf8 = require('../encoding/utf8');
var long = require('../encoding/long');

module.exports = {
	enc: function (plaintext, key) {
		var v = long.enc(utf8.enc(plaintext).replace(/%20/g,' '));
		if (v.length <= 1) {
			v[1] = 0;
		}

		var k = long.enc(utf8.enc(key).slice(0,16)),
			n = v.length,
			z = v[n-1],
			y = v[0],
			delta = 0x9E3779B9,
			mx,
			e,
			q = Math.floor(6 + 52/n),
			sum = 0;

		while (q-- > 0) {
			sum += delta;
			e = sum>>>2 & 3;
			for (var p = 0; p < n; p++) {
				y = v[(p+1) % n];
				mx = (z>>>5 ^ y<<2) + (y>>>3 ^ z<<4) ^ (sum^y) + (k[p&3 ^ e] ^ z);
				z = v[p] += mx;
			}
		}
		return long.dec(v);
	},

	dec: function (ciphertext, key) {
		var k = long.enc(utf8.enc(key).slice(0,16)), 
			v = long.enc(ciphertext),
			n = v.length;
		var z = v[n-1], y = v[0], delta = 0x9E3779B9;
		var mx, e, q = Math.floor(6 + 52/n), sum = q*delta;
		while (sum != 0) {
			e = sum>>>2 & 3;
			for (var p = n-1; p >= 0; p--) {
				z = v[p>0 ? p-1 : n-1];
				mx = (z>>>5 ^ y<<2) + (y>>>3 ^ z<<4) ^ (sum^y) + (k[p&3 ^ e] ^ z);
				y = v[p] -= mx;
			}
			sum -= delta;
		}
		return utf8.dec(long.dec(v).replace(/\0+$/,''));
	}
};