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
if (!window.cyphrd) window.cyphrd = {};
if (!window.cyphrd.crypto) window.cyphrd.crypto = {};

(function (crypto)
{
	crypto.endian =
	{
		// Convert a raw string to an array of big-endian words
		// Characters >255 have their high-byte silently ignored.
		encode: function(input)
		{
			var output = Array(input.length >> 2);
			for (var i = 0; i < output.length; i++)
			{
				output[i] = 0;
			}

			for (var i = 0; i < input.length * 8; i += 8)
			{
				output[i >> 5] |= (input.charCodeAt(i / 8) & 0xFF) << (24 - i % 32);
			}

			return output;
		},

		// Convert an array of big-endian words to a string
		decode: function(input)
		{
			var output = '';
			for (var i = 0; i < input.length * 32; i += 8)
			{
				output += String.fromCharCode((input[i >> 5] >>> (24 - i % 32)) & 0xFF);
			}
			return output;
		}
	};

})(cyphrd.crypto);
