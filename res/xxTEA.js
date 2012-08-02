//
// 'Block' Tiny Encryption Algorithm xxtea
// (c) 2002-2006 Chris Veness <scripts@movable-type.co.uk>
//
// Algorithm: David Wheeler & Roger Needham, Cambridge University Computer Lab
//            http://www.cl.cam.ac.uk/ftp/papers/djw-rmn/djw-rmn-tea.html (1994)
//            http://www.cl.cam.ac.uk/ftp/users/djw3/xtea.ps (1997)
//            http://www.cl.cam.ac.uk/ftp/users/djw3/xxtea.ps (1998)
//
// JavaScript implementation: Chris Veness, Movable Type Ltd: www.movable-type.co.uk
// http://www.movable-type.co.uk/scripts/TEAblock.html
//
// You are welcome to re-use these scripts [without any warranty express or implied] provided 
// you retain my copyright notice and when possible a link to my website (under LGPL license).
// If you have any queries or find any problems, please contact Chris Veness.
//
//
//

Crypto.register('xxTEA', '1.0', {
	encrypt: function (plaintext, key) {
		if (plaintext.length == 0) return('');
		var v = this.strToLongs(escape(plaintext).replace(/%20/g,' '));
		if (v.length <= 1) v[1] = 0;
		var k = this.strToLongs(key.slice(0,16)),
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
 		return this.escCtrlCh(this.longsToStr(v));
	},

	decrypt: function (ciphertext, key) {
		if (ciphertext.length == 0) return('');
		var k = this.strToLongs(key.slice(0,16)), 
			v = this.strToLongs(this.unescCtrlCh(ciphertext)),
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
		return unescape(this.longsToStr(v).replace(/\0+$/,''));
	},

	strToLongs: function (s) {
		var ll = Math.ceil(s.length/4);
		var l = new Array(ll);
		for (var i=0; i<ll; i++) {
			l[i] = s.charCodeAt(i*4)
				+ (s.charCodeAt(i*4+1)<<8)
				+ (s.charCodeAt(i*4+2)<<16)
				+ (s.charCodeAt(i*4+3)<<24);
		}
		return l;
	},

	longsToStr: function (l) {
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
	},
	
	escCtrlCh: function (str) {  // escape control chars etc which might cause problems with encrypted texts
   	return str.replace(/[\0\t\n\v\f\r\xa0'"!]/g, function(c) { return '!' + c.charCodeAt(0) + '!'; });
	},

	unescCtrlCh: function (str) {  // unescape potentially problematic nulls and control characters
		return str.replace(/!\d\d?\d?!/g, function(c) { return String.fromCharCode(c.slice(1,-1)); });
	}	
});

String.implement({
	tea_encode: function(key,pars) {
		return Crypto.xxTEA.encode(this,key);
	},

	tea_decode: function(key,pars) {
		return Crypto.xxTEA.decode(this,key);
	}
});
