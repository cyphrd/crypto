var assert = require('assert');
var crypto = require('..');

describe('pbkdf2', function () {
	it('sha1', function (done) {
		var testCompleted = 0;

		crypto.pbkdf2(crypto.sha1, 'password', 'salt', 1, 10, function (hash) {
			assert.equal(hash, '0c60c80f961f0e71f3a9');
			testCompleted++;
			if (testCompleted === 3) {
				done();
			}
		});

		crypto.pbkdf2(crypto.sha1, 'password', 'salt', 1, 20, function (hash) {
			assert.equal(hash, '0c60c80f961f0e71f3a9b524af6012062fe037a6');
			testCompleted++;
			if (testCompleted === 3) {
				done();
			}
		});

		crypto.pbkdf2(crypto.sha1, 'passwordPASSWORDpassword', 'saltSALTsaltSALTsaltSALTsaltSALTsalt', 4096, 13, function (hash) {
			assert.equal(hash, '3d2eec4fe41c849b80c8d83662');
			testCompleted++;
			if (testCompleted === 3) {
				done();
			}
		});
	});

	/*it('sha256', function (done) {
		var testCompleted = 0;

		crypto.pbkdf2(crypto.sha256, 'password', 'salt', 1, 10, function (hash) {
			assert.equal(hash, '120fb6cffcf8b32c43e7');
			testCompleted++;
			if (testCompleted === 3) {
				done();
			}
		});

		// crypto.pbkdf2(crypto.sha256, 'password', 'salt', 1, 20, function (hash) {
		// 	assert.equal(hash, '120fb6cffcf8b32c43e7');
		// 	testCompleted++;
		// 	if (testCompleted === 3) {
		// 		done();
		// 	}
		// });

		crypto.pbkdf2(crypto.sha256, 'passwordPASSWORDpassword', 'saltSALTsaltSALTsaltSALTsaltSALTsalt', 4096, 20, function (hash) {
			assert.equal(hash, '348c89dbcbd32b2f32d814b8116e84cf2b17347e');
			testCompleted++;
			if (testCompleted === 3) {
				done();
			}
		});
	});*/
});
