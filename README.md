# cyphrd.js: javascript encryption library

A collection of encryption and hashing modules, works with Node.js, require.js or directly in a browser. Modules are usually taken from other open source projects (see file heads), then updated to improve specification support (lots of unit testing) and performance.


## Modules

### Hash functions
[Cryptographic hashing](https://en.wikipedia.org/wiki/Cryptographic_hash_function)
is a way to take arbitrary data and return a fixed-size result (hash value) so that
any change to the data will have a change in the resulting value. There are many
ways to use a hash function, from message authentication, data integrity and data indexing.

* [md5](https://en.wikipedia.org/wiki/MD5)
* [ripemd](https://en.wikipedia.org/wiki/RIPEMD)
* [sha1](https://en.wikipedia.org/wiki/SHA-1)
* [sha2](https://en.wikipedia.org/wiki/SHA-2)
* [whirlpool](https://en.wikipedia.org/wiki/Whirlpool_(cryptography))

#### Key expansion

* [bcrypto](https://en.wikipedia.org/wiki/Bcrypt)
* [pbkdf2](https://en.wikipedia.org/wiki/PBKDF)

### Symmetric

* [aes](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) (rijndael)
* [rc4](https://en.wikipedia.org/wiki/RC4)


### Asymmetric (public-private key)

* [rsa](https://en.wikipedia.org/wiki/RSA_(algorithm))


### Encodings

 * base64
 * endian
 * hex
 * utf8


### Utilities

 * passphrases: a utility to identify password guessability
 * [srp](https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol): secure remote password protocol

## How to use

The usage varies by the type of library (hashing, symmetric, asymmetric) and there are utilities for key generation, password security improvement and more.

### Hashing

The simple, straightest forward usage for a hash function is:

	var cyphrd = require('cyphrd');

	var result = crypto.sha256('abc').hex();

The supported hash modules are:

	crypto.md5
	crypto.sha1
	crypto.sha256
	crypto.sha512

Each is used in the same way. Each module has an array of uses. When you run hashing synchronously, you are given a `HashResult` object in return.

	var cyphrd = require('cyphrd');

	var hash = crypto.sha256('abc');

The `HashResult` has a ton of useful things available, like:

	hash.hex(); // returns the result as a hexadecimal string.
	hash.b64(); // returns the result as a base64 string.
	hash.endian(); // returns the result as a byte array of endian numbers.
	hash.raw(); // return the raw (binary) result.

Each hash module that supports it, also can has a `hmac` method:

	crypto.sha1.hmac('key', 'data'); // returns a computed HAMC `HashResult` object.

