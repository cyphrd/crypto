goog.provide('cyphrd.crypto.base64');

goog.require('goog.crypt.base64');

cyphrd.crypto.base64.encode = function(input) {
	return goog.crypt.base64.encodeString(input);
};

cyphrd.crypto.base64.decode = function(input) {
	return goog.crypt.base64.decodeString(input);
};

// _keyStr : "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",

// encode : function (input) {
// 	var output = "";
// 	var chr1, chr2, chr3, enc1, enc2, enc3, enc4;
// 	var i = 0, keyStr = this._keyStr;

// 	while (i < input.length) {

// 		chr1 = input.charCodeAt(i++);
// 		chr2 = input.charCodeAt(i++);
// 		chr3 = input.charCodeAt(i++);

// 		enc1 = chr1 >> 2;
// 		enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
// 		enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
// 		enc4 = chr3 & 63;

// 		if (isNaN(chr2)) {
// 			enc3 = enc4 = 64;
// 		} else if (isNaN(chr3)) {
// 			enc4 = 64;
// 		}
// 		var output = output +
// 			keyStr.charAt(enc1) + keyStr.charAt(enc2) +
// 			keyStr.charAt(enc3) + keyStr.charAt(enc4);
// 	}

// 	return output;
// },

// decode : function (input) {
// 	var output = "";
// 	var chr1, chr2, chr3;
// 	var enc1, enc2, enc3, enc4;
// 	var i = 0, keyStr = this._keyStr;

// 	input = input.replace(/[^A-Za-z0-9\+\/\=]/g, "");

// 	while (i < input.length) {

// 		enc1 = keyStr.indexOf(input.charAt(i++));
// 		enc2 = keyStr.indexOf(input.charAt(i++));
// 		enc3 = keyStr.indexOf(input.charAt(i++));
// 		enc4 = keyStr.indexOf(input.charAt(i++));

// 		chr1 = (enc1 << 2) | (enc2 >> 4);
// 		chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
// 		chr3 = ((enc3 & 3) << 6) | enc4;

// 		output = output + String.fromCharCode(chr1);

// 		if (enc3 != 64) {
// 			output = output + String.fromCharCode(chr2);
// 		}
// 		if (enc4 != 64) {
// 			output = output + String.fromCharCode(chr3);
// 		}

// 	}

// 	return output;
// },

// Tests: {
// 	Sanity: function(){
// 		var str = Crypto.encode('UTF8', Crypto.utils.hashx('abc123', 1, 1));
// 		var encoded = Crypto.encode('Base64', str);
// 		var decoded = Crypto.decode('Base64', encoded);
// 		return str == decoded;
// 	},

// 	Truism: function(){
// 		var str = Crypto.encode('UTF8', 'abc123');
// 		return Crypto.encode('Base64', str) == "YWJjMTIz";
// 	}
// }
