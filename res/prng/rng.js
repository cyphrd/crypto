/**
 * JavaScript Crypto library by Cyphrd
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

goog.provide('cyphrd.crypto.rng');
goog.provide('cyphrd.crypto.SecureRandom')

goog.require('goog.events');

/**
 * Pool size must be a multiple of 4 and greater than 32.
 * An array of bytes the size of the pool
 */
cyphrd.crypto.rng.psize = 256;
// cyphrd.crypto.rng.state = null;
cyphrd.crypto.rng.pool = [];
cyphrd.crypto.rng.pptr = 0;

/**
 * Add a byte to the entropy vector
 */
cyphrd.crypto.rng.addByte = function(b) {
	cyphrd.crypto.rng.pool[cyphrd.crypto.rng.pptr++] = b;
};

/**
 * Mix in a 32-bit integer into the pool
 */
cyphrd.crypto.rng.add32 = function(x) {
	// for (var i = 0; i < 4; i++) {
	// 	this.addByte(w & 0xFF);
	// 	w >>= 8;
	// }

	cyphrd.crypto.rng.pool[cyphrd.crypto.rng.pptr++] ^= x & 255;
	cyphrd.crypto.rng.pool[cyphrd.crypto.rng.pptr++] ^= (x >> 8) & 255;
	cyphrd.crypto.rng.pool[cyphrd.crypto.rng.pptr++] ^= (x >> 16) & 255;
	cyphrd.crypto.rng.pool[cyphrd.crypto.rng.pptr++] ^= (x >> 24) & 255;

	if (cyphrd.crypto.rng.pptr >= cyphrd.crypto.rng.psize)
		cyphrd.crypto.rng.pptr -= cyphrd.crypto.rng.psize;
};

/**
 * Mix in the current time (w/milliseconds) into the pool
 */
cyphrd.crypto.rng.addTime = function() {
	cyphrd.crypto.rng.add32(+(new Date));
};

// Initialize the pool with junk if needed.
(function() {
	cyphrd.crypto.rng.addTime();

	// see if the browser supports provided random numbers
	if (window.crypto && window.crypto.getRandomValues) {
		var ints = new Uint32Array(cyphrd.crypto.rng.psize / 4);
		window.crypto.getRandomValues(ints);

		for (var i = 0; i < ints.length; i++) {
			cyphrd.crypto.rng.add32(ints[i]);
		}
	}
	
	// get a starting point for a pool from Math.random
	else {
		while(cyphrd.crypto.rng.pptr < cyphrd.crypto.rng.psize) {
			var t = Math.floor(65536 * Math.random());
			cyphrd.crypto.rng.pool[cyphrd.crypto.rng.pptr++] = t >>> 8;
			cyphrd.crypto.rng.pool[cyphrd.crypto.rng.pptr++] = t & 255;
		}
	}

	// listen for entropy from the client
	goog.events.listen(window, 'click', function(event) {
		cyphrd.crypto.rng.addTime();
		cyphrd.crypto.rng.add32(event.screenX);
		cyphrd.crypto.rng.add32(event.screenY);
	});

	var countMouseMoves = 0,
		maxMouseMoved = 500;

	var unlisten = goog.events.listen(window, 'mousemove', function(event) {
		cyphrd.crypto.rng.addTime();
		cyphrd.crypto.rng.add32(event.screenX);
		cyphrd.crypto.rng.add32(event.screenY);

		countMouseMoves++;

		if (countMouseMoves > maxMouseMoved)
			goog.events.unlistenByKey(unlisten);
	});
})();

/**
 * @constructor
 */
cyphrd.crypto.SecureRandom = function() {
	this.i = 0;
	this.j = 0;
	this.S = [];

	cyphrd.crypto.rng.addTime();
	this.init(cyphrd.crypto.rng.pool);

	for(cyphrd.crypto.rng.pptr = 0; cyphrd.crypto.rng.pptr < cyphrd.crypto.rng.pool.length; ++cyphrd.crypto.rng.pptr)
		cyphrd.crypto.rng.pool[cyphrd.crypto.rng.pptr] = 0;

	cyphrd.crypto.rng.pptr = 0;
};

cyphrd.crypto.SecureRandom.prototype.init = function(key) {
	var i, j, t;

	for(i = 0; i < 256; ++i)
		this.S[i] = i;

	j = 0;

	for(i = 0; i < 256; ++i) {
		j = (j + this.S[i] + key[i % key.length]) & 255;
		t = this.S[i];
		this.S[i] = this.S[j];
		this.S[j] = t;
	}

	this.i = 0;
	this.j = 0;
};

cyphrd.crypto.SecureRandom.prototype.getByte = function() {
	var t;
	this.i = (this.i + 1) & 255;
	this.j = (this.j + this.S[this.i]) & 255;

	t = this.S[this.i];

	this.S[this.i] = this.S[this.j];
	this.S[this.j] = t;

	return this.S[(t + this.S[this.i]) & 255];
};

cyphrd.crypto.SecureRandom.prototype.nextBytes = function(ba) {
	for (var i = 0; i < ba.length; ++i)
		ba[i] = this.getByte();
};
