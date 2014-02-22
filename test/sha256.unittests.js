var assert = require('assert');
var crypto = require('..');

describe('sha256', function () {
	it('truism', function () {
		assert.equal(
			crypto.sha256('abc').hex(),
			'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
		);
	});
});
