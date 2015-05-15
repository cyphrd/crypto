/**
 * Pool size must be a multiple of 4 and greater than 32.
 * An array of bytes the size of the pool
 */
var pool = {
	maxSize: 256,
	numbers: [],
	pptr: 0,

	/**
	 * Add a byte to the entropy vector
	 */
	addByte: function(b) {
		pool.numbers[pool.pptr++] = b;
	},

	/**
	 * Mix in a 32-bit integer into the pool
	 */
	add32: function(x) {
		pool.numbers[pool.pptr++] ^= x & 255;
		pool.numbers[pool.pptr++] ^= (x >> 8) & 255;
		pool.numbers[pool.pptr++] ^= (x >> 16) & 255;
		pool.numbers[pool.pptr++] ^= (x >> 24) & 255;

		if (pool.pptr >= pool.maxSize) {
			pool.pptr -= pool.maxSize;
		}
	},

	/**
	 * Mix in the current time (w/milliseconds) into the pool
	 */
	addTime: function() {
		pool.add32(+new Date());
	}
};

// initialize the pool of randomness
pool.addTime();

// see if the browser supports provided random numbers
if (window.crypto && window.crypto['getRandomValues']) {
	var ints = new Uint32Array(pool.maxSize / 4);
	window.crypto['getRandomValues'](ints);

	for (var i = 0; i < ints.length; i++) {
		pool.add32(ints[i]);
	}
}

// get a starting point for a pool from Math.random
else {
	while (pool.pptr < pool.maxSize) {
		var t = Math.floor(65536 * Math.random());
		pool.numbers[pool.pptr++] = t >>> 8;
		pool.numbers[pool.pptr++] = t & 255;
	}
}

// listen for entropy from the client
window.addEventListener('click', function (event) {
	pool.addTime();
	pool.add32(event.screenX);
	pool.add32(event.screenY);
});

module.exports = pool;