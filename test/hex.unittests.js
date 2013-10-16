describe("hex", function()
{
    describe("sanity", function()
    {
        it("should result in expected base64 value after encoding", function()
        {
            var s = cyphrd.crypto.sha512.raw('abc123');
            var encoded = cyphrd.crypto.hex.encode(s);
            var decoded = cyphrd.crypto.hex.decode(encoded);
            chai.assert.equal(s, decoded);
        });
    });
});