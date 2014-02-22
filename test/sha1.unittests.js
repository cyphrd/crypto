var assert = require('assert');
var crypto = require('..');

describe('sha1', function () {
	it('truism', function () {
		assert.equal(
			crypto.sha1('abc').hex(),
			'a9993e364706816aba3e25717850c26c9cd0d89d'
		);
	});
});
