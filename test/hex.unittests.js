var assert = require('assert');
var crypto = require('..');

describe('hex', function()
{
    describe('sanity', function()
    {
        it('result should match expected', function()
        {
            // returns a binary string
            var s = crypto.sha512('abc123').raw();

            // encode string, then decode it to verify
            var encoded = crypto.hex.enc(s);
            var decoded = crypto.hex.dec(encoded);
            assert.equal(s, decoded);
        });
    });
});