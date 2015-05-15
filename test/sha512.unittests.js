'use strict';

var assert = require('assert');
var crypto = require('..');

describe('sha512', function() {
	it('truism.hex', function() {
		assert.equal(
			crypto.sha512('').hex(),
			'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce' +
			'47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e'
		);

		assert.equal(
			crypto.sha512('a').hex(),
			'1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f53' +
			'02860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75'
		);

		assert.equal(
			crypto.sha512('012345678901234567890123456789012345678901234567890123456789').hex(),
			'e3e33e00eec4753ea01c134b21c52badc44d364648ba2321ff18aa213902759b' +
			'04f7f0dbfff426acec097c09476adcd0666d2d86e8cc2fcd4f7c549acbfbfd94'
		);

		assert.equal(
			crypto.sha512.hex('test'),
			'ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db2' +
			'7ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff'
		);
	});

	it('truism.b64', function() {
		assert.equal(
			crypto.sha512.b64('abc'),
			'3a81oZNherrMQXNJriBBMRLm+k6JqX6iCp7u5ktV05ohkpkqJ0/BqDa6PCOj/uu9RU1EI2Q86A4qmslPpUyknw=='
		);
	});

	it('utf8 unsafe', function() {
		var chinese = '版面变化复';

		assert.notEqual(
			crypto.sha512(chinese).hex(),
			'76705ad2a6ca98b9ebf1d060493a18663a69e6b99eebc2d12766789fe00d4de9' +
			'72f5106c9178a25cf59ea0fa19014666495da16bef14de1ddddebba9ef4efc18'
		);
	});

	it('utf8 safe', function() {
		var chinese = '版面变化复';

		assert.equal(
			crypto.sha512.safe(chinese).hex(),
			'76705ad2a6ca98b9ebf1d060493a18663a69e6b99eebc2d12766789fe00d4de9' +
			'72f5106c9178a25cf59ea0fa19014666495da16bef14de1ddddebba9ef4efc18'
		);
	});

	it('FIPS-180 Vectors', function() {
		assert.equal(
			crypto.sha512('abc').hex(),
			'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a' +
			'2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f'
		);

		assert.equal(
			crypto.sha512('abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu').hex(),
			'8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018' +
			'501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909'
		);

		assert.equal(
			crypto.sha512(Array(1000000+1).join('a')).hex(),
			'e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb' +
			'de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b'
		);
	});
});
