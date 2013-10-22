var keyStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
var _chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
var chars = _chars.split('');

module.exports =
{
	encodeString: function (input)
	{
		var output = "",
			chr1, chr2, chr3,
			enc1, enc2, enc3, enc4,
			i = 0;

		while (i < input.length)
		{
			chr1 = input.charCodeAt(i++);
			chr2 = input.charCodeAt(i++);
			chr3 = input.charCodeAt(i++);

			enc1 = chr1 >> 2;
			enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
			enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
			enc4 = chr3 & 63;

			if (isNaN(chr2))
			{
				enc3 = enc4 = 64;
			}
			else if (isNaN(chr3))
			{
				enc4 = 64;
			}
			var output = output +
				keyStr.charAt(enc1) + keyStr.charAt(enc2) +
				keyStr.charAt(enc3) + keyStr.charAt(enc4);
		}

		return output;
	},

	// Takes a Nx16x1 byte array and converts it to Base64
	encodeByteArray: function (b, withBreaks)
	{
		var flatArr = [],
			b64 = '',
			i,
			broken_b64,
			totalChunks = Math.floor(b.length * 16 / 3);

		for (i = 0; i < b.length * 16; i++)
		{
			flatArr.push(b[Math.floor(i / 16)][i % 16]);
		}

		for (i = 0; i < flatArr.length; i = i + 3)
		{
			b64 += chars[flatArr[i] >> 2];
			b64 += chars[((flatArr[i] & 3) << 4) | (flatArr[i + 1] >> 4)];
			if ( flatArr[i + 1] !== undefined )
			{
				b64 += chars[((flatArr[i + 1] & 15) << 2) | (flatArr[i + 2] >> 6)];
			}
			else
			{
				b64 += '=';
			}

			if (flatArr[i + 2] !== undefined)
			{
				b64 += chars[flatArr[i + 2] & 63];
			}
			else
			{
				b64 += '=';
			}
		}

		if (withBreaks !== false)
		{
			// OpenSSL is super particular about line breaks
			broken_b64 = b64.slice(0, 64) + '\n';
			for (i = 1; i < (Math.ceil(b64.length / 64)); i++)
			{
				broken_b64 += b64.slice(i * 64, i * 64 + 64) + (Math.ceil(b64.length / 64) === i + 1 ? '': '\n');
			}
			return broken_b64;
		}

		return b64;
	},

	decodeString: function (input)
	{
		var output = "",
			chr1, chr2, chr3,
			enc1, enc2, enc3, enc4,
			i = 0;

		input = input.replace(/[^A-Za-z0-9\+\/\=]/g, "");

		while (i < input.length)
		{
			enc1 = keyStr.indexOf(input.charAt(i++));
			enc2 = keyStr.indexOf(input.charAt(i++));
			enc3 = keyStr.indexOf(input.charAt(i++));
			enc4 = keyStr.indexOf(input.charAt(i++));

			chr1 = (enc1 << 2) | (enc2 >> 4);
			chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
			chr3 = ((enc3 & 3) << 6) | enc4;

			output = output + String.fromCharCode(chr1);

			if (enc3 != 64)
			{
				output = output + String.fromCharCode(chr2);
			}
			if (enc4 != 64)
			{
				output = output + String.fromCharCode(chr3);
			}

		}

		return output;
	},

	decodeByteArray: function(string)
	{
		var flatArr = [],
			c = [],
			b = [],
			i;

		string = string.replace(/\n/g, '');

		for (i = 0; i < string.length; i = i + 4) {
			c[0] = _chars.indexOf(string.charAt(i));
			c[1] = _chars.indexOf(string.charAt(i + 1));
			c[2] = _chars.indexOf(string.charAt(i + 2));
			c[3] = _chars.indexOf(string.charAt(i + 3));

			b[0] = (c[0] << 2) | (c[1] >> 4);
			b[1] = ((c[1] & 15) << 4) | (c[2] >> 2);
			b[2] = ((c[2] & 3) << 6) | c[3];
			flatArr.push(b[0], b[1], b[2]);
		}
		flatArr = flatArr.slice(0, flatArr.length - (flatArr.length % 16));
		return flatArr;
	}
};

// allow this to act like a pollyfill
// if (win && !win.btoa)
// {
// 	win.btoa = crypto.base64.encodeString;
// }

// if (win && !win.atob)
// {
// 	win.atob = crypto.base64.decodeString;
// }