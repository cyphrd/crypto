'use strict';

var assert = require('assert');
var crypto = require('..');

describe('sha512', function() {
	describe('Truism Verification', function() {
		it('hex', function() {
			assert.equal(
				crypto.sha512('abc').hex(),
				'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a' +
				'2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f'
			);
		});

		it('b64', function() {
			assert.equal(
				crypto.sha512.b64('abc'),
				'3a81oZNherrMQXNJriBBMRLm+k6JqX6iCp7u5ktV05ohkpkqJ0/BqDa6PCOj/uu9RU1EI2Q86A4qmslPpUyknw=='
			);
		});

		it('hex', function()
		{
			assert.equal(
				crypto.sha512.hex('test'),
				'ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db2' +
				'7ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff'
			);
		});
	});

	describe('UTF-8 Verification', function() {
		it('without utf8 safe, should not work', function() {
			var chinese = '版面变化复';

			assert.notEqual(
				crypto.sha512(chinese).hex(),
				'76705ad2a6ca98b9ebf1d060493a18663a69e6b99eebc2d12766789fe00d4de9' +
				'72f5106c9178a25cf59ea0fa19014666495da16bef14de1ddddebba9ef4efc18'
			);
		});

		// it('with utf8 safe', function() {
		// 	var chinese = '版面变化复';

		// 	assert.equal(
		// 		crypto.sha512.safe(chinese).hex(),
		// 		'76705ad2a6ca98b9ebf1d060493a18663a69e6b99eebc2d12766789fe00d4de9' +
		// 		'72f5106c9178a25cf59ea0fa19014666495da16bef14de1ddddebba9ef4efc18'
		// 	);
		// });
	});
});