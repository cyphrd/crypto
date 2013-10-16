describe("utf8", function()
{
    describe("sanity", function()
    {
        it("should result in expected utf8 value after encoding", function()
        {
            var s = cyphrd.utils.hashx('abc123', 1, 1);
            var encoded = cyphrd.crypto.utf8.encode(s);
            var decoded = cyphrd.crypto.utf8.decode(encoded);

            chai.assert.equal(s, decoded);
        });
    });
});