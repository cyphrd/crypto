cyphrd.cryto: javascript encryption library
===========================================

[View the project page](http://cyphrd.github.io/crypto)

cyphrd.crypto is a collection of javascript encryption and security libraries written so that it can be used regularly client-side, with require.js or with Node.js. The libraries are tested for integrity and compatibility with the algorithm's specifications and is written for performance in mind.


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


supported algorithms
------------------

* [aes](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) (rijndael)
* [rc4](https://en.wikipedia.org/wiki/RC4)
* [rsa](https://en.wikipedia.org/wiki/RSA_(algorithm))
* [xxtea](https://en.wikipedia.org/wiki/XXTEA)


supported encodings
------------------

 * base64
 * endian
 * hex
 * utf8


included utilities
------------------

 * passwords: a utility to identify password guessability
 * [srp](https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol): secure remote password protocol