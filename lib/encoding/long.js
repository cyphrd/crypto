module.exports =
{
	enc: function (s)
	{
		var ll = Math.ceil(s.length/4);
		var l = new Array(ll);
		for (var i=0; i<ll; i++) {
			l[i] = s.charCodeAt(i*4) + (s.charCodeAt(i*4+1)<<8) + (s.charCodeAt(i*4+2)<<16) + (s.charCodeAt(i*4+3)<<24);
		}
		return l;
	},

	dec: function (l)
	{
		var a = new Array(l.length);
		for (var i=0; i<l.length; i++) {
			a[i] = String.fromCharCode(
				l[i] & 0xFF,
				l[i]>>>8 & 0xFF,
				l[i]>>>16 & 0xFF,
				l[i]>>>24 & 0xFF
			);
		}
		return a.join('');
	}
};