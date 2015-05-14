/**
 * Crypto library by Cyphrd
 * Copyright (C) 2012 Cyphrd.com
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

module.exports = {
	// encoding
	b64: require('./encoding/b64'),
	endian: require('./encoding/endian'),
	hex: require('./encoding/hex'),
	utf8: require('./encoding/utf8'),

	// symmetric
	aes: require('./encryption/aes'),
	rc4: require('./encryption/rc4'),

	// hash functions
	md5: require('./hash/md5'), // 128
	rmd: require('./hash/ripemd'), // RIPEMD-160
	sha1: require('./hash/sha1'), // sha-128
	sha256: require('./hash/sha256'), // sha2-256
	sha512: require('./hash/sha512'), // sha2-512

	// key-expansion hash functions
	pbkdf2: require('./hash/pbkdf2'),

	// utilities
	passphrases: require('./passphrases'),
	utils: require('./utils')
};