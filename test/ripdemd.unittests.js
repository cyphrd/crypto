var assert = require('assert');
var crypto = require('..');

describe('ripemd', function () {
	it('truism', function () {
		assert.equal(
			crypto.rmd.safe('abc').hex(),
			'8eb208f7e05d987a9b044a8e98c6b087f15a0bfc'
		);
	});
});
