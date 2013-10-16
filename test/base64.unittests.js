describe("base64", function()
{
    var assert = chai.assert;

    describe("sanity", function()
    {
        var str = 'abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123';
        var expected = 'YWJjMTIzYWJjMTIzYWJjMTIzYWJjMTIzYWJjMTIzYWJjMTIzYWJjMTIzYWJjMTIzYWJjMTIzYWJjMTIz';
        var encoded;

        it("should result in expected base64 value after encoding", function()
        {
            encoded = cyphrd.crypto.base64.encode(str);
            assert.equal(encoded, expected);
        });

        it("should result in original value after decoding", function()
        {
            assert.equal(cyphrd.crypto.base64.decode(encoded), str);
        });
    });

    describe("truism tests", function()
    {
        it("should match values", function()
        {
            assert.equal(cyphrd.crypto.base64.encode('abc123'), 'YWJjMTIz');
        });
    });
});