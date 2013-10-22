var assert = require("assert")
var crypto = require('..');

describe("utf8", function()
{
	describe("sanity", function()
	{
		it("binary data", function()
		{
			var s = crypto.utils.hashx('abc123', 1, 1);
			var encoded = crypto.utf8.enc(s);
			var decoded = crypto.utf8.dec(encoded);

			assert.equal(s, decoded);
		});

		it("utf8 data", function()
		{
			var chinese = " 版面变化复";
			var enc = crypto.utf8.enc(chinese);
			var dec = crypto.utf8.dec(enc);

			assert.equal(dec, chinese);
		});
	});
});