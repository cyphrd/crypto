var assert = require("assert")
var crypto = require('..');

describe("base64", function()
{
	describe("sanity", function()
	{
		var str = 'abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123';
		var expected = 'YWJjMTIzYWJjMTIzYWJjMTIzYWJjMTIzYWJjMTIzYWJjMTIzYWJjMTIzYWJjMTIzYWJjMTIzYWJjMTIz';
		var encoded;

		it("should result in expected base64 value after encoding", function()
		{
			encoded = crypto.b64.encodeString(str);
			assert.equal(encoded, expected);
		});

		it("should result in original value after decoding", function()
		{
			assert.equal(crypto.b64.decodeString(encoded), str);
		});
	});

	describe("truism tests", function()
	{
		it("should match values", function()
		{
			assert.equal(crypto.b64.encodeString('abc123'), 'YWJjMTIz');
		});
	});

	// describe("browser truism tests", function()
	// {
	// 	it("browser should support base64 natively", function()
	// 	{
	// 		assert.notEqual(btoa, crypto.base64.encodeString);
	// 	});

	// 	it("should match", function()
	// 	{
	// 		assert.equal(btoa('hello world'), crypto.base64.encodeString('hello world'));
	// 		assert.equal(btoa('8247198571298571928'), crypto.base64.encodeString('8247198571298571928'));
	// 		assert.equal(btoa('{hello: true, this: false, that: "muahaha"}'), crypto.base64.encodeString('{hello: true, this: false, that: "muahaha"}'));
	// 	});

	// 	it("utf8 test", function()
	// 	{
	// 		assert.equal(btoa('©'), crypto.base64.encodeString('©'));
	// 	});
	// });
});