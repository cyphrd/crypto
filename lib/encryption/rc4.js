function rc4 (txt, key, N, dval) {
	function exc(v,a,b) {
		var t = v[a];
		v[a] = v[b];
		v[b] = t;
	}
	
	var num = [], sbox = [], b=0;
	
	for (var i=0;i<=255;i++) {
		sbox[i] = i;
		num[i] = key.charCodeAt(i % key.length);
	}
	
	// improvement (with some bugs - for example with N=5
	for (var u=0;u<N;u++) {
		for (var i=0;i<=255;i++) {
			b = (b + sbox[i] + num[i]) % 256;
			exc(sbox,i,b);
		}
	}
	//
	
	var k=0, j=0, ret = "", val;
	for (var i=0;i<txt.length;i++) {
		 k = (k + 1) % 256;
		 j = (j + sbox[k]) % 256;
		 exc(sbox,k,j);
		 val = txt.charCodeAt(i) ^ sbox[(sbox[k] + sbox[j]) % 256];
		 
		// dval produces not-reversible numeric strings:
		 
		 ret += dval ? val : String.fromCharCode(val);
	}
	return ret;
}

rc4.enc = function (text, key, rounds) {
	return rc4(text, key, rounds || 1);
};

rc4.dec = function (text, key, rounds) {
	return rc4(text, key, rounds || 1);
};

module.exports = rc4;
