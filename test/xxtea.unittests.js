var assert = require("assert")
var crypto = require('..');
crypto.xxtea = require('../lib/encryption/xxtea');

describe("xxtea", function()
{
	describe("truism: test known data", function()
	{
		it("encrypt", function()
		{
			var enc = crypto.b64.enc(crypto.xxtea.enc("hello world", "pass"));
			assert.equal(enc, "3vQKngPxFn2NHqqOd4N82w==");
		});
	});
});
