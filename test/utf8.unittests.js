var assert = require("assert")
var crypto = require('..');

describe("utf8", function()
{
	describe("sanity: test generated data", function()
	{
		it("binary data", function()
		{
			var s = crypto.utils.hashx('abc123', 1, 1);
			var enc = crypto.utf8.enc(s);
			var dec = crypto.utf8.dec(enc);

			assert.equal(s, dec);
		});
	});

	describe("truism: test known data", function()
	{
		it("utf8 data", function()
		{
			var chinese = " 版面变化复";
			var enc = crypto.utf8.enc(chinese);
			var dec = crypto.utf8.dec(enc);

			assert.equal(dec, chinese);
		});
	});
});