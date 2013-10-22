var assert = require("assert")
var crypto = require('..');

describe("hex", function()
{
    describe("sanity", function()
    {
        it("should result in expected base64 value after encoding", function()
        {
            var s = crypto.sha512.raw('abc123');
            var encoded = crypto.hex.encode(s);
            var decoded = crypto.hex.decode(encoded);
            assert.equal(s, decoded);
        });
    });
});