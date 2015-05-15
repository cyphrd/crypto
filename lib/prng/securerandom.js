var pool = require('./pool');

function SecureRandom() {
	this.i = 0;
	this.j = 0;
	this.S = [];

	pool.addTime();
	this.init(pool.numbers);

	for (pool.pptr = 0; pool.pptr < pool.numbers.length; ++pool.pptr) {
		pool.numbers[pool.pptr] = 0;
	}

	pool.pptr = 0;
}

SecureRandom.prototype.init = function(key) {
	var i, j, t;

	for (i = 0; i < 256; ++i) {
		this.S[i] = i;
	}

	j = 0;

	for (i = 0; i < 256; ++i) {
		j = (j + this.S[i] + key[i % key.length]) & 255;
		t = this.S[i];
		this.S[i] = this.S[j];
		this.S[j] = t;
	}

	this.i = 0;
	this.j = 0;
};

SecureRandom.prototype.getByte = function() {
	var t;
	this.i = (this.i + 1) & 255;
	this.j = (this.j + this.S[this.i]) & 255;

	t = this.S[this.i];

	this.S[this.i] = this.S[this.j];
	this.S[this.j] = t;

	return this.S[(t + this.S[this.i]) & 255];
};

SecureRandom.prototype.nextBytes = function(ba) {
	var i = 0, l = ba.length;
	for (; i < l; ++i) {
		ba[i] = this.getByte();
	}
};

module.exports = SecureRandom;