var assert = require("assert")
var crypto = require('..');

describe("base64", function()
{
	describe("sanity", function()
	{
		var str = 'abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123';
		var expected = 'YWJjMTIzYWJjMTIzYWJjMTIzYWJjMTIzYWJjMTIzYWJjMTIzYWJjMTIzYWJjMTIzYWJjMTIzYWJjMTIz';
		var encoded;

		it("verify encoding", function()
		{
			encoded = crypto.b64.enc(str);
			assert.equal(encoded, expected);
		});

		it("verify decoding", function()
		{
			assert.equal(crypto.b64.dec(encoded), str);
		});
	});

	describe("Truism Verification", function()
	{
		it("should match", function()
		{
			assert.equal(crypto.b64.enc('abc123'), 'YWJjMTIz');
			assert.equal('aGVsbG8gd29ybGQ=', crypto.b64.enc('hello world'));
			assert.equal('ODI0NzE5ODU3MTI5ODU3MTkyOA==', crypto.b64.enc('8247198571298571928'));
			assert.equal('e2hlbGxvOiB0cnVlLCB0aGlzOiBmYWxzZSwgdGhhdDogIm11YWhhaGEifQ==', crypto.b64.enc('{hello: true, this: false, that: "muahaha"}'));
		});
	});

	describe("UTF-8 Verification", function()
	{
		it("should match", function()
		{
			var chinese = " 版面变化复";
			var enc = crypto.b64.enc(crypto.utf8.enc(chinese));
			var dec = crypto.utf8.dec(crypto.b64.dec(enc));

			assert.equal(chinese, dec);
		});
	});
});