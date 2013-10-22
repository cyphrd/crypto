define(['../core'], function (crypto)
{
	var raw = function (data)
	{
		this.data = data;
	};

	raw.prototype.raw = function()
	{
		return this.data;
	};

	raw.prototype.utf8 = function()
	{
		return crypto.utf8.encode(this.data);
	};

	raw.prototype.string = raw.prototype.utf8;
	raw.prototype.toString = raw.prototype.utf8;

	raw.prototype.base64 = function()
	{
		return crypto.base64.encode(this.data);
	};

	raw.prototype.hex = function()
	{
		return crypto.hex.encode(this.data);
	};

	crypto.raw = raw;
	return crypto;
});