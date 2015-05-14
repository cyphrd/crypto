cyphrd.cryto: javascript encryption library
===========================================

[View the project page](http://cyphrd.github.io/crypto)

A collection of encryption and hashing modules, works with Node.js, require.js or directly in a browser. Modules are usually taken from other open source projects (see file heads), then updated to improve specification support (lots of unit testing) and performance.


supported hash functions
------------------
[Cryptographic hashing](https://en.wikipedia.org/wiki/Cryptographic_hash_function)
is a way to take arbitrary data and return a fixed-size result (hash value) so that
any change to the data will have a change in the resulting value. There are many
ways to use a hash function, from message authentication, data integrity and data indexing.

* [bcrypto](https://en.wikipedia.org/wiki/Bcrypt)
* [md5](https://en.wikipedia.org/wiki/MD5)
* [pbkdf2](https://en.wikipedia.org/wiki/PBKDF)
* [ripemd](https://en.wikipedia.org/wiki/RIPEMD)
* [sha1](https://en.wikipedia.org/wiki/SHA-1)
* [sha2](https://en.wikipedia.org/wiki/SHA-2)
* [whirlpool](https://en.wikipedia.org/wiki/Whirlpool_(cryptography))


supported symmetric
------------------

* [aes](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) (rijndael)
* [rc4](https://en.wikipedia.org/wiki/RC4)


supported asymmetric (public-private key)
------------------

* [rsa](https://en.wikipedia.org/wiki/RSA_(algorithm))


supported encodings
------------------

 * base64
 * endian
 * hex
 * utf8


included utilities
------------------

 * passphrases: a utility to identify password guessability
 * [srp](https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol): secure remote password protocol