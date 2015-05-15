var assert = require('assert');
var crypto = require('..');

describe('md5', function () {
	it('truism', function () {
		assert.equal(
			crypto.md5('abc').hex(),
			'900150983cd24fb0d6963f7d28e17f72'
		);
	});
});
