goog.provide('cyphrd.crypto.hex');

// 0 - lowercase, 1 - uppercase
cyphrd.crypto.hex._case = 0;

cyphrd.crypto.hex.encode = function(string) {
    var hex_tab = cyphrd.crypto.hex._case ? '0123456789ABCDEF' : '0123456789abcdef';
    var output = '';
    var x;
    for(var i = 0; i < string.length; i++) {
      x = string.charCodeAt(i);
      output += hex_tab.charAt((x >>> 4) & 0x0F) + hex_tab.charAt(x&0x0F);
    }
    return output;
};

/**
 * @param {string} hexstring
 * @param {number=} n
 */
cyphrd.crypto.hex.decode = function(hexstring, n) {
	if (!hexstring)
		return '';

	var h = '';
	var t = n ? n : hexstring.length;// : 32;

	for (var j=0;j<t;j=j+2)
		h += String.fromCharCode(parseInt(hexstring.substring(j,j+2),16));

	return h;
};

// Tests: {
// 	Sanity: function(){
// 		// this will return a nice string with no HEX characters
// 		var s = Crypto.SHA512.raw('abc');
// 		var encoded = Crypto.encode('HEX', s);
// 		var decoded = Crypto.decode('HEX', encoded);

// 		// after encoding and then decoding, we should have
// 		// what we had before encoding.
// 		return s == decoded;
// 	}
// }
