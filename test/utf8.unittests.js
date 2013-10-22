var assert = require("assert")
var crypto = require('..');

describe("utf8", function()
{
	describe("sanity", function()
	{
		it("should result in expected utf8 value after encoding", function()
		{
			var s = crypto.utils.hashx('abc123', 1, 1);
			var encoded = crypto.utf8.encode(s);
			var decoded = crypto.utf8.decode(encoded);

			assert.equal(s, decoded);
		});
	});
});