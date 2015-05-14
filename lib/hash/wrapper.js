'use strict';

var b64 = require('../encoding/b64');
var endian = require('../encoding/endian');
var hex = require('../encoding/hex');
var utf8 = require('../encoding/utf8');

function HashResult(result) {
	this.result = result;
}

HashResult.prototype.raw = function _raw() {
	return endian.dec(this.result);
};

HashResult.prototype.hex = function _hex(uppercase) {
	return hex.enc(this.raw(), uppercase === true);
};

HashResult.prototype.b64 = function _b64() {
	return b64.enc(this.raw());
};

HashResult.prototype.endian = function _endian() {
	return this.result;
};

module.exports = function (hashFunction) {
	function hash(data) {
		// console.log('|' + data + '|');
		var result = hashFunction(endian.enc(data), data.length * 8);
		return new HashResult(result);
	}

	// ensure data is utf8 safe before hashing
	hash.safe = function (data) {
		return hash(utf8.enc(data));
	};

	hash.hmac = function (key, data) {
		var bkey = hash(key).endian();
		var ipad = Array(16);
		var opad = Array(16);

		for (var i = 0; i < 16; i++) {
			ipad[i] = bkey[i] ^ 0x36363636;
			opad[i] = bkey[i] ^ 0x5C5C5C5C;
		}

		var h = hashFunction(ipad.concat(endian.enc(data)), hashFunction.ipadOffset + data.length * 8);
		return endian.dec(hashFunction(opad.concat(h), hashFunction.opadOffset + 512));
	};

	hash.hmacSafe = function (key, data) {
		key = utf8.enc(key);
		data = utf8.enc(data);
		return hash.hmac(key, data);
	};

	// utility methods
	hash.hex = function (data) {
		return hash(data).hex();
	};

	hash.b64 = function (data) {
		return hash(data).b64();
	};

	hash._ = hashFunction;

	return hash;
};