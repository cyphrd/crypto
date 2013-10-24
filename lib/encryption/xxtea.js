var utf8 = require('../encoding/utf8');

function escCtrlCh (str) {  // escape control chars etc which might cause problems with encrypted texts
	return str; //str.replace(/[\0\t\n\v\f\r\xa0'"!]/g, function(c) { return '!' + c.charCodeAt(0) + '!'; });
}

function unescCtrlCh (str) {  // unescape potentially problematic nulls and control characters
	return str; //str.replace(/!\d\d?\d?!/g, function(c) { return String.fromCharCode(c.slice(1,-1)); });
}

function strToLongs (s) {
	var ll = Math.ceil(s.length/4);
	var l = new Array(ll);
	for (var i=0; i<ll; i++) {
		l[i] = s.charCodeAt(i*4)
			+ (s.charCodeAt(i*4+1)<<8)
			+ (s.charCodeAt(i*4+2)<<16)
			+ (s.charCodeAt(i*4+3)<<24);
	}
	console.log(l);
	return l;
}

function longsToStr (l) {
	var a = new Array(l.length);
	for (var i=0; i<l.length; i++) {
		a[i] = String.fromCharCode(
			l[i] & 0xFF,
			l[i]>>>8 & 0xFF,
			l[i]>>>16 & 0xFF,
			l[i]>>>24 & 0xFF
		);
	}
	return a.join('');
}

var xxtea = {
	enc: function (plaintext, key) {
		var v = strToLongs(utf8.enc(plaintext).replace(/%20/g,' '));
		if (v.length <= 1) {
			v[1] = 0;
		}

		var k = strToLongs(utf8.enc(key).slice(0,16)),
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
		return escCtrlCh(longsToStr(v));
	},

	dec: function (ciphertext, key) {
		var k = strToLongs(utf8.enc(key).slice(0,16)), 
			v = strToLongs(unescCtrlCh(ciphertext)),
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
		return utf8.dec(longsToStr(v).replace(/\0+$/,''));
	}
};

module.exports = xxtea;