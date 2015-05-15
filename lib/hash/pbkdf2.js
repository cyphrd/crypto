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

/**
 * Original work by parvez@anandam.com, available at http://anandam.com/pbkdf2
 */

var endian = require('../encoding/endian.big');
var hex = require('../encoding/hex');

var chrsz = 8;  /* bits per input character. 8 - ASCII; 16 - Unicode  */

// use a set timeout to try to run in background
var setI = typeof setImmediate == 'function' ? setImmediate : (function (f) { setTimeout(f, 0); });

/**
 * @param keyLength {number} Key length, as number of bytes
 * @param onComplete {function} The function to call with the result
 */
pbkdf2 = function (hash, password, salt, iterations, keyLength, onComplete) {
	// Remember the password and salt
	var m_bpassword = endian.enc(password);

	// Total number of iterations
	if (typeof iterations !== 'number')
	{
		throw new Error('`iterations` must be a number.');
	}

	// Run iterations in chunks instead of all at once, so as to not block.
	// Define size of chunk here; adjust for slower or faster machines if necessary.
	var m_iterations_in_chunk = 10;

	// Completed iteration counter
	var iDone = 0;

	// The hash cache
	var m_hash = null;

	// The length (number of bytes) of the output of the pseudo-random function.
	// Since HMAC-SHA1 is the standard, and what is used here, it's 20 bytes.
	var m_hash_length = 20;

	// Number of hash-sized blocks in the derived key (called 'l' in RFC2898)
	var m_total_blocks = Math.ceil(keyLength/m_hash_length);

	// Start computation with the first block
	var m_current_block = 1;

	// Used in the HMAC-SHA1 computations
	var m_ipad = new Array(16);
	var m_opad = new Array(16);

	// This is where the result of the iterations gets sotred
	var m_buffer = new Array(0x0,0x0,0x0,0x0,0x0);
	
	// The resulting expanded key
	var result = "";

	// track when we started the computation, to return the time to compute on complete
	var started = Date.now();
	
	// Set up the HMAC-SHA1 computations
	if (m_bpassword.length > 16) {
		m_bpassword = hash._(m_bpassword, password.length * chrsz);
	}

	for (var i = 0; i < 16; ++i) {
		m_ipad[i] = m_bpassword[i] ^ 0x36363636;
		m_opad[i] = m_bpassword[i] ^ 0x5C5C5C5C;
	}

	// The workhorse
	var do_PBKDF2_iterations = function()
	{
		var iteration = m_iterations_in_chunk;
		if (iterations - iDone < m_iterations_in_chunk) {
			iteration = iterations - iDone;
		}

		for (var i = 0; i < iteration; ++i) {
			// compute HMAC-SHA1 
			if (iDone == 0)
			{
				var salt_block = salt +
					String.fromCharCode(m_current_block >> 24 & 0xF) +
					String.fromCharCode(m_current_block >> 16 & 0xF) +
					String.fromCharCode(m_current_block >>  8 & 0xF) +
					String.fromCharCode(m_current_block       & 0xF);

				m_hash = hash._(m_ipad.concat(endian.enc(salt_block)), 512 + salt_block.length * 8);
				m_hash = hash._(m_opad.concat(m_hash), 512 + 160);
			}
			else
			{
				m_hash = hash._(m_ipad.concat(m_hash), 512 + m_hash.length * 32);
				m_hash = hash._(m_opad.concat(m_hash), 512 + 160);
			}

			for (var j = 0; j < m_hash.length; ++j) {
				m_buffer[j] ^= m_hash[j];
			}

			iDone++;
		}

		// if we are not done yet
		if (iDone < iterations) {
			setI(do_PBKDF2_iterations);
		}
		else if (m_current_block < m_total_blocks)
		{
			// Compute the next block (T_i in RFC 2898)
			
			result += hex.enc(endian.dec(m_buffer));
		
			m_current_block++;
			m_buffer = new Array(0x0,0x0,0x0,0x0,0x0);
			iDone = 0;

			setI(do_PBKDF2_iterations);
		}
		else
		{
			// We've computed the final block T_l; we're done.
			var tmp = hex.enc(endian.dec(m_buffer));
			result += tmp.substr(0, (keyLength - (m_total_blocks - 1) * m_hash_length) * 2 );

			// Call the result callback function
			if (typeof onComplete === 'function') {
				onComplete(result, Date.now() - started);
			}
		}
	}

	setI(do_PBKDF2_iterations);
};

module.exports = pbkdf2;

// require('./wrapper')(pbkdf2, {
// 	hmac: false
// });
