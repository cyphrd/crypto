module.exports = {

	/*
	 * Add integers, wrapping at 2^32. This uses 16-bit operations internally
	 * to work around bugs in some JS interpreters.
	 */
	safeAdd: function (x, y) {
		var lsw = (x & 0xFFFF) + (y & 0xFFFF);
		var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
		return (msw << 16) | (lsw & 0xFFFF);
	},

	/*
	 * Bitwise rotate a 32-bit number to the left.
	 */
	bit_rol: function (num, cnt) {
		return (num << cnt) | (num >>> (32 - cnt));
	}

};
