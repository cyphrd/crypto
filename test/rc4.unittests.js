var assert = require("assert")
var crypto = require('..');

describe("rc4", function()
{
	describe("truism: test known data", function()
	{
		it("string data", function()
		{
			var s = "abc",
				key = "900150983cd24fb0d6963f7d28e17f72",
				enc = crypto.rc4.enc(s, key),
				dec = crypto.rc4.dec(enc, key);

			assert.equal(s, dec);
		});
	});
});
