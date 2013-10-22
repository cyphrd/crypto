module.exports =
{
	enc: function (string, uppercase)
	{
			var hex_tab = uppercase === true ? '0123456789ABCDEF' : '0123456789abcdef';
			var output = '';
			var x;

			for(var i = 0; i < string.length; i++)
			{
				x = string.charCodeAt(i);
				output += hex_tab.charAt((x >>> 4) & 0x0F) + hex_tab.charAt(x&0x0F);
			}

			return output;
	},

	dec: function (hexstring, n)
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