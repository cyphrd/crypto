/**
 * JavaScript Crypto library by Cyphrd
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

/*
 * The four arguments to the constructor of the PBKDF2 object are 
 * the password, salt, number of iterations and number of bytes in
 * generated key. This follows the RFC 2898 definition: PBKDF2 (P, S, c, dkLen)
 *
 * The method deriveKey takes two parameters, both callback functions:
 * the first is used to provide status on the computation, the second
 * is called with the result of the computation (the generated key in hex).
 *
 * Example of use:
 *
 *    <script src="sha1.js"></script>
 *    <script src="pbkdf2.js"></script>
 *    <script>
 *    var mypbkdf2 = new PBKDF2("mypassword", "saltines", 1000, 16);
 *    var status_callback = function(percent_done) {
 *        document.getElementById("status").innerHTML = "Computed " + percent_done + "%"};
 *    var result_callback = function(key) {
 *        document.getElementById("status").innerHTML = "The derived key is: " + key};
 *    mypbkdf2.deriveKey(status_callback, result_callback);
 *    </script>PBKDF2
 *    <div id="status"></div>
 *
 */

var chrsz = 16;  /* bits per input character. 8 - ASCII; 16 - Unicode  */

/*
 * Convert a raw string to an array of big-endian words
 * Characters >255 have their high-byte silently ignored.
 */
function rstr2binb(input)
{
  var output = Array(input.length >> 2);
  for(var i = 0; i < output.length; i++)
    output[i] = 0;
  for(var i = 0; i < input.length * 8; i += 8)
    output[i>>5] |= (input.charCodeAt(i / 8) & 0xFF) << (24 - i % 32);
  return output;
}

// convert binary array to hex string
function binb2hex (binarray) {
	var hexcase = 0; /* hex output format. 0 - lowercase; 1 - uppercase */
	var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
	var str = "";
	for (var i = 0; i < binarray.length * 4; i++) {
		str += hex_tab.charAt((binarray[i>>2] >> ((3 - i%4)*8+4)) & 0xF) + hex_tab.charAt((binarray[i>>2] >> ((3 - i%4)*8  )) & 0xF);
	}
	return str;
}

/*
 * Convert an array of big-endian words to a string
 */
function binb2rstr(input)
{
  var output = "";
  for(var i = 0; i < input.length * 32; i += 8)
    output += String.fromCharCode((input[i>>5] >>> (24 - i % 32)) & 0xFF);
  return output;
}


 /*
 * Convert a raw string to a hex string
 */
function rstr2hex(input)
{
  try { hexcase } catch(e) { hexcase=0; }
  var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
  var output = "";
  var x;
  for(var i = 0; i < input.length; i++)
  {
    x = input.charCodeAt(i);
    output += hex_tab.charAt((x >>> 4) & 0x0F)
           +  hex_tab.charAt( x        & 0x0F);
  }
  return output;
}

// use a set timeout to try to run in background
var setI = typeof setImmediate == 'function' ? setImmediate : (function (f) { window.setTimeout(f, 0); });

/**
 * @param keyLength {number} Key length, as number of bytes
 * @param onProgress {function} The function to call with status after computing every chunk
 * @param onComplete {function} The function to call with the result
 */
module.exports = function (hash, password, salt, iterations, keyLength, onProgress, onComplete) {
	// Remember the password and salt
	var m_bpassword = rstr2binb(password);

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
	
	// The result
	var m_key = "";

	// This object
	var m_this_object = this;

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

				m_hash = hash._(m_ipad.concat(rstr2binb(salt_block)), 512 + salt_block.length * 8);
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

		// Call the status callback function
		if (typeof onProgress === 'function') {
			onProgress( (m_current_block - 1 + iDone/iterations) / m_total_blocks);
		}

		// if we are not done yet
		if (iDone < iterations) {
			setI(do_PBKDF2_iterations);
		}
		else if (m_current_block < m_total_blocks)
		{
			// Compute the next block (T_i in RFC 2898)
			
			m_key += rstr2hex(binb2rstr(m_buffer));
		
			m_current_block++;
			m_buffer = new Array(0x0,0x0,0x0,0x0,0x0);
			iDone = 0;

			setI(do_PBKDF2_iterations);
		}
		else
		{
			// We've computed the final block T_l; we're done.
			var tmp = rstr2hex(binb2rstr(m_buffer));
			m_key += tmp.substr(0, (keyLength - (m_total_blocks - 1) * m_hash_length) * 2 );

			// Call the result callback function
			if (typeof onComplete === 'function') {
				onComplete(m_key, Date.now() - started);
			}
		}
	}

	setI(do_PBKDF2_iterations);
};
