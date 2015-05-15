/**
 * Crypto library by Cyphrd
 * Copyright (C) 2012 Cyphrd.com
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * Original work by Paul Johnston, available at http://pajhome.org.uk/crypt/md5/sha1.html
 */

var utils = require('./utils');

 /*
 * Calculate the SHA-1 of an array of big-endian words, and a bit length
 */
var sha1 = function binb_sha1(x, len) {
	/* append padding */
	x[len >> 5] |= 0x80 << (24 - len % 32);
	x[((len + 64 >> 9) << 4) + 15] = len;

	var w = Array(80);
	var a = 1732584193;
	var b = -271733879;
	var c = -1732584194;
	var d = 271733878;
	var e = -1009589776;

	for (var i = 0; i < x.length; i += 16) {
		var olda = a;
		var oldb = b;
		var oldc = c;
		var oldd = d;
		var olde = e;

		for (var j = 0; j < 80; j++) {
			if (j < 16) {
				w[j] = x[i + j];
			} else {
				w[j] = utils.bit_rol(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
			}

			var t = utils.safeAdd(utils.safeAdd(utils.bit_rol(a, 5), sha1_ft(j, b, c, d)), utils.safeAdd(utils.safeAdd(e, w[j]), sha1_kt(j)));
			e = d;
			d = c;
			c = utils.bit_rol(b, 30);
			b = a;
			a = t;
		}

		a = utils.safeAdd(a, olda);
		b = utils.safeAdd(b, oldb);
		c = utils.safeAdd(c, oldc);
		d = utils.safeAdd(d, oldd);
		e = utils.safeAdd(e, olde);
	}

	return Array(a, b, c, d, e);
}

/*
 * Perform the appropriate triplet combination function for the current
 * iteration
 */
function sha1_ft(t, b, c, d) {
	if (t < 20) return (b & c) | ((~b) & d);
	if (t < 40) return b ^ c ^ d;
	if (t < 60) return (b & c) | (b & d) | (c & d);
	return b ^ c ^ d;
}

/*
 * Determine the appropriate additive constant for the current iteration
 */
function sha1_kt(t) {
	return (t < 20) ? 1518500249 : (t < 40) ? 1859775393 : (t < 60) ? -1894007588 : -899497514;
}

module.exports = require('./wrapper')(sha1, {
	endian: 'big',
	ipadOffset: 512,
	opadOffset: 160
});
