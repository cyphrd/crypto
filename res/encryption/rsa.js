Crypto.register('RSA', '1.0', {

	byte2Hex: function (b) {
		if(b < 0x10)
			return "0" + b.toString(16);
		else
			return b.toString(16);
	},

	// PKCS#1 (type 2, random) pad input string s to n bytes, and return a bigint
	pkcs1pad2: function (s,n) {
		if(n < s.length + 11) {
			alert("Message too long for RSA");
			return null;
		}
		var ba = [],
		i = s.length - 1;
		while(i >= 0 && n > 0) ba[--n] = s.charCodeAt(i--);
		ba[--n] = 0;
		var rng = new SecureRandom(),
		x = [];
		while(n > 2) { // random non-zero pad
			x[0] = 0;
			while(x[0] == 0) rng.nextBytes(x);
			ba[--n] = x[0];
		}
		ba[--n] = 2;
		ba[--n] = 0;
		return new BigInteger(ba);
	},

	// Undo PKCS#1 (type 2, random) padding and, if valid, return the plaintext
	pkcs1unpad2: function (d,n) {
		var b = d.toByteArray();
		var i = 0;
		while(i < b.length && b[i] == 0) ++i;
		if(b.length-i != n-1 || b[i] != 2)
			return null;
		++i;
		while(b[i] != 0)
			if(++i >= b.length) return null;
		var ret = "";
		while(++i < b.length)
			ret += String.fromCharCode(b[i]);
		return ret;
	},

	//Key: Crypto.RSAKey,
	//RSAKey: Crypto.RSAKey,

	// Return the PKCS#1 RSA decryption of "ctext".
	// "ctext" is an even-length hex string and the output is a plain string.
	decode: function (enctext, rsa, pars) {
		var plaintext = '', hash = JSON.decode(enctext);

		hash.each(function(enctext){
			plaintext += rsa.decrypt(enctext);
		}.bind(plaintext));

		return plaintext;
	},

	// Return the PKCS#1 RSA encryption of "text" as an even-length hex string
	encode: function(plaintext, rsa, pars){
		var hash = [], max = ((rsa.n.bitLength()+7)>>3) - 11;

		while(plaintext.length){
			hash.push( rsa.encrypt( plaintext.substring(0, max) ) );
			plaintext = plaintext.substring(max);
		}

		return JSON.encode(hash);
	}

});