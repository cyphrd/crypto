var assert = require('assert');
var crypto = require('..');

describe('sha256', function () {
	it('truism', function () {
		assert.equal(
			crypto.sha256('').hex(),
			'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
		);

		assert.equal(
			crypto.sha256('a').hex(),
			'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb'
		);

		assert.equal(
			crypto.sha256('012345678901234567890123456789012345678901234567890123456789').hex(),
			'5e43c8704ac81f33d701c1ace046ba9f257062b4d17e78f3254cbf243177e4f2'
		);
	});

	it('FIPS-180 Vectors', function () {
		assert.equal(
			crypto.sha256('abc').hex(),
			'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
		);

		assert.equal(
			crypto.sha256('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq').hex(),
			'248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1'
		);

		assert.equal(
			crypto.sha256(Array(1000000+1).join('a')).hex(),
			'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0'
		);
	});
});
