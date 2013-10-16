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
	var hex_case = 0; // 0 - lowercase, 1 - uppercase

	crypto.hex =
	{
		encode: function (string)
		{
				var hex_tab = hex_case ? '0123456789ABCDEF' : '0123456789abcdef';
				var output = '';
				var x;
				for(var i = 0; i < string.length; i++)
				{
					x = string.charCodeAt(i);
					output += hex_tab.charAt((x >>> 4) & 0x0F) + hex_tab.charAt(x&0x0F);
				}
				return output;
		},

		/**
		 * @param {string} hexstring
		 * @param {number=} n
		 */
		decode: function (hexstring, n)
		{
			if (!hexstring)
			{
				return '';
			}

			var h = '';
			var t = n ? n : hexstring.length;// : 32;

			for (var j=0;j<t;j=j+2)
			{
				h += String.fromCharCode(parseInt(hexstring.substring(j,j+2),16));
			}

			return h;
		}
	};

})(cyphrd.crypto);
