/**
 * Module dependencies.
 */

/**
 * Module exports.
 */

module.exports = {
	// encoding methods
	b64: require('./encoding/b64'),
	endian: require('./encoding/endian'),
	hex: require('./encoding/hex'),
	utf8: require('./encoding/utf8'),

	// encryption methods
	aes: require('./encryption/aes'),
	rc4: require('./encryption/rc4'),
	xxtea: require('./encryption/xxtea'),

	// hash functions
	md5: require('./hash/md5'), // 128
	pbkdf2: require('./hash/pbkdf2'),
	sha1: require('./hash/sha1'), // sha-128
	sha256: require('./hash/sha256'), // sha2-256
	sha512: require('./hash/sha512'), // sha2-512

	passphrases: require('./passphrases'),
	utils: require('./utils')
};