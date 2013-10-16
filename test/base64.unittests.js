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

    describe("browser truism tests", function()
    {
        it("browser should support base64 natively", function()
        {
            assert.notEqual(window.btoa, cyphrd.crypto.base64.encode);
        });

        it("should match", function()
        {
            assert.equal(window.btoa('hello world'), cyphrd.crypto.base64.encode('hello world'));
            assert.equal(window.btoa('8247198571298571928'), cyphrd.crypto.base64.encode('8247198571298571928'));
            assert.equal(window.btoa('{hello: true, this: false, that: "muahaha"}'), cyphrd.crypto.base64.encode('{hello: true, this: false, that: "muahaha"}'));
        });

        it("utf8 test", function()
        {
            assert.equal(window.btoa('©'), cyphrd.crypto.base64.encode('©'));
        });
    });
});