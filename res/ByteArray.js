var ByteArray_abstract = new Class({

	'toString': function() {
		return "Clipperz.ByteArray_abstract";
	},
	
	'equals': function(aValue) {
		return (this.compare(aValue) == 0);
	},
	
	'compare': function(aValue) {
		var result;
		var i;
		
		result = Tools.compare(this.length(), aValue.length());
		i = this.length();
		
		while ((result == 0) && (i>0)) {
			i--;
			result = Tools.compare(this.byteAtIndex(i), aValue.byteAtIndex(i));
		}
		
		return result;
	},
	
	'clone': function() {
		throw 'AbstractMethod';
	},

	'newInstance': function() {
		throw 'AbstractMethod';
	},
	
	'reset': function() {
		throw 'AbstractMethod';
	},
	
	'length': function() {
		throw 'AbstractMethod';
	},

	'checkByteValue': function(aValue) {
		if ((aValue & 0xff) != aValue) {
			Console.warn("ByteArray.appendByte: the provided value (0x" + aValue.toString(16) + ") is not a byte value.");
			throw Clipperz.ByteArray.exception.InvalidValue;
		}
	},
	
	'xorMergeWithBlock': function(aBlock, anAllignment, paddingMode) {
		var result;
		var a, b;
		var aLength;
		var bLength;			
		var i, c;
		
		if (this.length() > aBlock.length()) {
			a = this;
			b = aBlock;
		} else {
			a = aBlock;
			b = this;
		}

		aLength = a.length();
		bLength = b.length();

		if (aLength != bLength) {
			if (paddingMode == 'truncate') {
				if (anAllignment == 'left') {
					a = a.split(0, bLength);
				} else {
					a = a.split(aLength - bLength);
				}
			} else {
				var ii, cc;
				var padding;
				
				padding = this.newInstance();
				cc = aLength - bLength;
				for (ii=0; ii<cc; ii++) {
					padding.appendByte(0);
				}
				
				if (anAllignment == 'left') {
					b = b.appendBlock(padding);
				} else {
					b = padding.appendBlock(b);
				}
			}
		}

		result = this.newInstance();
		c = a.length();
		for (i=0; i<c; i++) {
			result.appendByte(a.byteAtIndex(i) ^ b.byteAtIndex(i));
		}

		return result;
	},

	'appendBlock': function(aBlock) {
		throw 'AbstractMethod';
	},

	'appendByte': function(aValue) {
		throw 'AbstractMethod';
	},

	'appendBytes': function(args) {
		var	values;
		var	i,c;

		if (args.constructor == Array) {
			values = args;
		} else {
			values = arguments;
		}

		c = values.length;
		for (i=0; i<c; i++) {
			this.appendByte(values[i]);
		}
		
		return this;
	},
	
	'appendWord': function(aValue, isLittleEndian) {
		var result;
		var processAsLittleEndian;
		
		processAsLittleEndian = isLittleEndian === true ? true : false;
		
		if (processAsLittleEndian) {
			result = this.appendBytes(	(aValue) & 0xff, (aValue >> 8) & 0xff, (aValue >> 16) & 0xff, (aValue >> 24) & 0xff	);	//	little endian
		} else {
			result = this.appendBytes(	(aValue >> 24) & 0xff, (aValue >> 16) & 0xff, (aValue >> 8) & 0xff, (aValue) & 0xff	);	//	big endian - DEFAULT
		}
		
		return result;
	},

	'appendWords': function(args) {
		var	values;
		var	i,c;

		if (args.constructor == Array) {
			values = args;
		} else {
			values = arguments;
		}

		c = values.length;
		for (i=0; i<c; i++) {
			this.appendWord(values[i], false);
		}
		
		return this;
	},

	'appendBigEndianWords': function(args) {
		var	values;
		var	i,c;

		if (args.constructor == Array) {
			values = args;
		} else {
			values = arguments;
		}

		c = values.length;
		for (i=0; i<c; i++) {
			this.appendWord(values[i], true);
		}
		
		return this;
	},

	'appendBinaryString': function (aBinaryString) {
		var i,c;
		
		c = aBinaryString.length;
		for (i=0; i<c; i++) {
			this.appendByte(aBinaryString.charCodeAt(i));
		};

		return this;
	},

	'byteAtIndex': function(anIndex) {
		throw 'AbstractMethod';
	},
	
	'setByteAtIndex': function(aValue, anIndex) {
		throw 'AbstractMethod';
	},

	'bitAtIndex': function(aBitPosition) {
		var result;
		var	bytePosition;
		var bitPositionInSelectedByte;
		var selectedByte;
		var selectedByteMask;
		
		bytePosition = this.length() - Math.ceil((aBitPosition + 1)/ 8);
		bitPositionInSelectedByte = aBitPosition % 8;
		selectedByte = this.byteAtIndex(bytePosition);

		if (bitPositionInSelectedByte > 0) {
			selectedByteMask = (1 << bitPositionInSelectedByte);
		} else {
			selectedByteMask = 1;
		}
		result = selectedByte & selectedByteMask ? 1 : 0;
		
		return result;
	},

	'bitBlockAtIndexWithSize': function(aBitPosition, aSize) {
		var result;
		var bitValue;
		var i,c;
		
		result = 0;
		c = aSize;
		for (i=0; i<c; i++) {
			bitValue = this.bitAtIndex(aBitPosition + i);
			result = result | bitValue << i;
		}
		
		return result;
	},
	
	'asString': function() {
		var	result;
		var	length;
		var	i;

		result = [];
		
		i = 0;
		length = this.length();
		
		while (i < length) {
			var	currentCharacter;
			var	currentByte;
			var	unicode;
			
			currentByte = this.byteAtIndex(i);
			
			if ((currentByte & 0x80) == 0x00 ) {		//	0xxxxxxx
				unicode = currentByte;
				currentCharacter = String.fromCharCode(unicode);
			} else if ((currentByte & 0xe0) == 0xc0 ) {	//	110xxxxx 10xxxxxx
				unicode = (currentByte & 0x1f) << 6;
				i++; currentByte = this.byteAtIndex(i);
				unicode = unicode | (currentByte & 0x3f);

				currentCharacter = String.fromCharCode(unicode);
			} else if ((currentByte & 0xf0) == 0xe0 ) {	//	1110xxxx 10xxxxxx 10xxxxxx
				unicode = (currentByte & 0x0f) << (6+6);
				i++; currentByte = this.byteAtIndex(i);
				unicode = unicode | ((currentByte & 0x3f) << 6);
				i++; currentByte = this.byteAtIndex(i);
				unicode = unicode | (currentByte & 0x3f);
				
				currentCharacter = String.fromCharCode(unicode);
			} else {									//	11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
				unicode = (currentByte & 0x07) << (6+6+6);
				i++; currentByte = this.byteAtIndex(i);
				unicode = unicode | ((currentByte & 0x3f) << (6+6));
				i++; currentByte = this.byteAtIndex(i);
				unicode = unicode | ((currentByte & 0x3f) << 6);
				i++; currentByte = this.byteAtIndex(i);
				unicode = unicode | (currentByte & 0x3f);
				
				currentCharacter = String.fromCharCode(unicode);
			}
			
			result.push(currentCharacter);
			i++;
		}

		return result.join("");
	},

	'toHexString': function() {
		throw 'AbstractMethod';
	},
	
	'base64map': "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
	'base64mapIndex': "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".split(''),

	'appendBase64String': function(aValue) {
		var i;
		var length;

		length = aValue.length;
		
		if ((length % 4) != 0) {
			Console.warn("the value passed to the 'ByteArray.setBase64Value' is not correct");
			throw Clipperz.ByteArray.exception.InvalidValue;
		}

		i = 0;
		while (i<length) {
			var value1, value2, value3, value4;
			var byte1, byte2, byte3;
			
			value1 = this.base64map.indexOf(aValue.charAt(i));
			value2 = this.base64map.indexOf(aValue.charAt(i+1));
			value3 = this.base64map.indexOf(aValue.charAt(i+2));
			value4 = this.base64map.indexOf(aValue.charAt(i+3));

			byte1 = (value1 << 2) | ((value2 & 0x30) >> 4);
			if (value3 != -1) {
				byte2 = ((value2 & 0x0f) << 4) | ((value3 & 0x3c) >> 2);

				if (value4 != -1) {
					byte3 = ((value3 & 0x03) << 6) | (value4);
				} else {
					byte3 = null;
				}
			} else {
				byte2 = null;
				byte3 = null;
			}

			this.appendByte(byte1);
			this.appendByte(byte2);
			this.appendByte(byte3);

			i += 4;
		}
		
		return this;
	},

	'toBase64String': function() {
		var result;
		var length;
		var i;
		var byte1, byte2, byte3;
		var char1, char2, char3, char4;
		
		i = 0;
		length = this.length();
		result = new Array(Math.ceil(length/3));
		
		while (i < length) {
			byte1 = this.byteAtIndex(i);
			if ((i+2) < length) {
				byte2 = this.byteAtIndex(i+1);
				byte3 = this.byteAtIndex(i+2);
			} else if ((i+2) == length) {
				byte2 = this.byteAtIndex(i+1);
				byte3 = null;
			} else {
				byte2 = null;
				byte3 = null;
			}
			
			char1 = this.base64mapIndex[byte1 >> 2];
			if (byte2 != null) {
				char2 = this.base64mapIndex[((byte1 & 0x03) << 4) | ((byte2 & 0xf0) >> 4)];
				if (byte3 != null) {
					char3 = this.base64mapIndex[((byte2 & 0x0f) << 2) | ((byte3 & 0xc0) >> 6)];
					char4 = this.base64mapIndex[(byte3 & 0x3f)];
				} else {
					char3 = this.base64mapIndex[(byte2 & 0x0f) << 2];
					char4 = "=";
				}
			} else {
				char2 = this.base64mapIndex[(byte1 & 0x03) << 4];
				char3 = "=";
				char4 = "=";
			}

			result.push(char1 + char2 + char3 + char4);
			
			i += 3;
		}

		return result.join("");
	},

	'base32map': "0123456789abcdefghjkmnpqrstvwxyz",
	'base32mapIndex': "0123456789abcdefghjkmnpqrstvwxyz".split(''),

	'appendBase32String': function(aValue) {
		var value;
		var i;
		var length;
		var value1, value2, value3, value4, value5, value6, value7, value8;
		var byte1, byte2, byte3, byte4, byte5;

		value = aValue.toLowerCase();
		value = value.replace(/[\s\-]/g, '');
		value = value.replace(/[0o]/g, '0');
		value = value.replace(/[1il]/g, '1');

		length = value.length;
		
		if ((length % 8) != 0) {
			Console.warn("the value passed to the 'ByteArray.setBase32Value' is not correct");
			throw Clipperz.ByteArray.exception.InvalidValue;
		}

		i = 0;
		while (i<length) {
			value1 = this.base32map.indexOf(value.charAt(i));
			value2 = this.base32map.indexOf(value.charAt(i+1));
			value3 = this.base32map.indexOf(value.charAt(i+2));
			value4 = this.base32map.indexOf(value.charAt(i+3));
			value5 = this.base32map.indexOf(value.charAt(i+4));
			value6 = this.base32map.indexOf(value.charAt(i+5));
			value7 = this.base32map.indexOf(value.charAt(i+6));
			value8 = this.base32map.indexOf(value.charAt(i+7));

			byte1 = byte2 = byte3 = byte4 = byte5 = null;
			
			byte1 = (value1 << 3) | ((value2 & 0x1c) >> 2);
			if (value3 != -1) {
				byte2 = ((value2 & 0x03) << 6) | (value3 << 1) | ((value4 & 0x10) >> 4);
				if (value5 != -1) {
					byte3 = ((value4 & 0x0f) << 4) | ((value5 & 0x1e) >> 1);
					if (value6 != -1) {
						byte4 = ((value5 & 0x01) << 7) | (value6 << 2) | ((value7 & 0x18) >> 3);
						if (value8 != -1) {
							byte5 = ((value7 & 0x07) << 5) | (value8);
						}
					}
				}
			}

			this.appendByte(byte1);
			this.appendByte(byte2);
			this.appendByte(byte3);
			this.appendByte(byte4);
			this.appendByte(byte5);

			i += 8;
		}

		return this;
	},

	'toBase32String': function() {
		var result;
		var length;
		var i;
		var byte1, byte2, byte3, byte4, byte5;
		var char1, char2, char3, char4, char5, char6, char7, char8;
		
		i = 0;
		length = this.length();
		result = new Array(Math.ceil(length/5));
		
		while (i < length) {
			byte1 = this.byteAtIndex(i);
			
			if ((i+4) < length) {
				byte2 = this.byteAtIndex(i+1);
				byte3 = this.byteAtIndex(i+2);
				byte4 = this.byteAtIndex(i+3);
				byte5 = this.byteAtIndex(i+4);
			} else if ((i+4) == length) {
				byte2 = this.byteAtIndex(i+1);
				byte3 = this.byteAtIndex(i+2);
				byte4 = this.byteAtIndex(i+3);
				byte5 = null;
			} else if ((i+3) == length) {
				byte2 = this.byteAtIndex(i+1);
				byte3 = this.byteAtIndex(i+2);
				byte4 = null;
				byte5 = null;
			} else if ((i+2) == length) {
				byte2 = this.byteAtIndex(i+1);
				byte3 = null;
				byte4 = null;
				byte5 = null;
			} else {
				byte2 = null;
				byte3 = null;
				byte4 = null;
				byte5 = null;
			}

			
			char1 = this.base32mapIndex[byte1 >> 3];
			char2 = char3 = char4 = char5 = char6 = char7 = char8 = "=";
			
			if (byte2 != null) {
				char2 = this.base32mapIndex[((byte1 & 0x07) << 2) | ((byte2 & 0xc0) >> 6)];
				char3 = this.base32mapIndex[((byte2 & 0x3e) >> 1)];
				if (byte3 != null) {
					char4 = this.base32mapIndex[((byte2 & 0x01) << 4) | ((byte3 & 0xf0) >> 4)];
					if (byte4 != null) {
						char5 = this.base32mapIndex[((byte3 & 0x0f) << 1) | ((byte4 & 0x80) >> 7)];
						char6 = this.base32mapIndex[(byte4 & 0x7c) >> 2];
						if (byte5 != null) {
							char7 = this.base32mapIndex[((byte4 & 0x03) << 3) | ((byte5 & 0xe0) >> 5)];
							char8 = this.base32mapIndex[(byte5 & 0x1f)];
						} else {
							char7 = this.base32mapIndex[(byte4 & 0x03) << 3];
						}
					} else {
						char5 = this.base32mapIndex[(byte3 & 0x0f) << 1];
					}

				} else {
					char4 = this.base32mapIndex[(byte2 & 0x01) << 4];
				}
			} else {
				char2 = this.base32mapIndex[(byte1 & 0x07) << 2];
			}

			result.push(char1 + char2 + char3 + char4 + char5 + char6 + char7 + char8);
			i += 5;
		}

		return result.join("");
	},
	
	'toBinaryString': function () {
		var	i, c;
		var result;

		result = '';

		c = this.length();
		for (i=0; i<c; i++) {
			result += String.fromCharCode(this.byteAtIndex(i));
		}
		
		return result;
	},

	'split': function(aStartingIndex, anEndingIndex) {
		throw 'AbstractMethod';
	},

	'increment': function() {
		var i;
		var done;
		
		done = false;
		i = this.length() - 1;
		
		while ((i>=0) && (done == false)) {
			var currentByteValue;
			
			currentByteValue = this.byteAtIndex(i);
			
			if (currentByteValue == 0xff) {
				this.setByteAtIndex(0, i);
				if (i>= 0) {
					i --;
				} else {
					done = true;
				}
			} else {
				this.setByteAtIndex(currentByteValue + 1, i);
				done = true;
			}
		}
	},
	
	'arrayValues': function() {
		throw 'AbstractMethod';
	}
});

var ByteArray_array = new Class({

	initialize: function (args) {
		if (typeof(args) != 'undefined') {
			if (args.constructor == Array) {
				this._value = args.slice(0);
			} else if (args.constructor == String) {
				var result;
				var	value;
				var i, c;
				
				if (args.indexOf("0x") == 0) {
				
					value = args.substring(2).toLowerCase();
					if (/[0123456789abcdef]*/.test(value)) {
						if ((value.length % 2) != 0) {
							value = "0" + value;
						}
					} else {
						Console.warn("ByteArray should be inizialized with an hex string.");
						throw 'InvalidValue';
					}

					c = value.length / 2
					result = new Array(c);
					for (i=0; i<c; i++) {
						result[i] = parseInt(value.substr(i*2, 2), 16);
					}

				} else {
					var unicode;
					result = [];
					c = args.length;
					for (i=0; i<c; i++) {
	//					Clipperz.ByteArray.pushUtf8BytesOfUnicodeChar(result, args.charCodeAt(i));

						unicode = args.charCodeAt(i);
						if (unicode <= 0x7f) {										//	0x00000000 - 0x0000007f -> 0xxxxxxx
							result.push(unicode);
					//	} else if ((unicode >= 0x80) && (unicode <= 0x7ff)) {		//	0x00000080 - 0x000007ff -> 110xxxxx 10xxxxxx
						} else if (unicode <= 0x7ff) {		//	0x00000080 - 0x000007ff -> 110xxxxx 10xxxxxx
							result.push((unicode >> 6) | 0xc0);
							result.push((unicode & 0x3F) | 0x80);
					//	} else if ((unicode >= 0x0800) && (unicode <= 0xffff)) {	//	0x00000800 - 0x0000ffff -> 1110xxxx 10xxxxxx 10xxxxxx
						} else if (unicode <= 0xffff) {	//	0x00000800 - 0x0000ffff -> 1110xxxx 10xxxxxx 10xxxxxx
							result.push((unicode >> 12) | 0xe0);
							result.push(((unicode >> 6) & 0x3f) | 0x80);
							result.push((unicode & 0x3f) | 0x80);
						} else {													//	0x00010000 - 0x001fffff -> 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
							result.push((unicode >> 18) | 0xf0);
							result.push(((unicode >> 12) & 0x3f) | 0x80);
							result.push(((unicode >> 6) & 0x3f) | 0x80);
							result.push((unicode & 0x3f) | 0x80);
						}
					}
				}
				
			
				this._value = result;
			} else {
				this._value = [];
				this.appendBytes(MochiKit.Base.extend(null, arguments));
			}
		} else {
			this._value = [];
		}
		
		return this;
	},

	'clone': function() {
		var result;
		
		result = this.newInstance();
		result.appendBytes(this._value);
		
		return result;
	},
	
	'newInstance': function() {
		return new ByteArray_array();
	},
	
	'reset': function() {
		this._value = [];
	},
	
	'length': function() {
		return (this._value.length);
	},
	
	'appendBlock': function(aBlock) {
		MochiKit.Base.extend(this._value, aBlock._value);
		
		return this;
	},

	'appendByte': function(aValue) {
		if (aValue != null) {
			this.checkByteValue(aValue);
			this._value.push(aValue);
		}
		
		return this;
	},

	'byteAtIndex': function(anIndex) {
		return this._value[anIndex];
	},
	
	'setByteAtIndex': function(aValue, anIndex) {
		var	missingBytes;
		
		this.checkByteValue(aValue);

		missingBytes = anIndex - this.length();
		
		if (missingBytes < 0) {
			this._value[anIndex] = aValue;
		} else if (missingBytes == 0) {
			this._value.push(aValue);
		} else {
			var i,c;
			
			c = missingBytes;
			for (i=0; i<c; i++) {
				this._value.push(0);
			}
			
			this._value.push(aValue);
		}
	},

	'toHexString': function() {
		var result;
		var i, c;
		
		result = "0x";
		c = this.length();
		for (i=0; i<c; i++) {
			result += Clipperz.ByteArray.byteToHex(this._value[i]);
		}
		
		return result;
	},
	
	'split': function(aStartingIndex, anEndingIndex) {
		var result;
		
		result = this.newInstance();
		result._value = this._value.slice(aStartingIndex, anEndingIndex ? anEndingIndex : this.length());
		
		return result;
	},

	'arrayValues': function() {
		return this._value.slice(0);
	}
});

var ByteArray = ByteArray_array;

ByteArray.byteToHex = function(aByte) {
	return ((aByte < 16) ? "0" : "") + aByte.toString(16);
}

ByteArray.unicodeToUtf8HexString = function(aUnicode) {
	var result;
	var	self;
	
	self = Clipperz.ByteArray;
	
	if (aUnicode <= 0x7f) {										//	0x00000000 - 0x0000007f -> 0xxxxxxx
		result = self.byteToHex(aUnicode);
	} else if (aUnicode <= 0x7ff) {		//	0x00000080 - 0x000007ff -> 110xxxxx 10xxxxxx
		result = self.byteToHex((aUnicode >> 6) | 0xc0);
		result += self.byteToHex((aUnicode & 0x3F) | 0x80);
	} else if (aUnicode <= 0xffff) {	//	0x00000800 - 0x0000ffff -> 1110xxxx 10xxxxxx 10xxxxxx
		result = self.byteToHex((aUnicode >> 12) | 0xe0);
		result += self.byteToHex(((aUnicode >> 6) & 0x3f) | 0x80);
		result += self.byteToHex((aUnicode & 0x3f) | 0x80);
	} else {													//	0x00010000 - 0x001fffff -> 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
		result = self.byteToHex((aUnicode >> 18) | 0xf0);
		result += self.byteToHex(((aUnicode >> 12) & 0x3f) | 0x80);
		result += self.byteToHex(((aUnicode >> 6) & 0x3f) | 0x80);
		result += self.byteToHex((aUnicode & 0x3f) | 0x80);
	}

	return result;
}

ByteArray.pushUtf8BytesOfUnicodeChar = function(anArray, aUnicode) {
	var	self;
	
	self = Clipperz.ByteArray;
	
	if (aUnicode <= 0x7f) {										//	0x00000000 - 0x0000007f -> 0xxxxxxx
		anArray.push(aUnicode);
	} else if (aUnicode <= 0x7ff) {		//	0x00000080 - 0x000007ff -> 110xxxxx 10xxxxxx
		anArray.push((aUnicode >> 6) | 0xc0);
		anArray.push((aUnicode & 0x3F) | 0x80);
	} else if (aUnicode <= 0xffff) {	//	0x00000800 - 0x0000ffff -> 1110xxxx 10xxxxxx 10xxxxxx
		anArray.push((aUnicode >> 12) | 0xe0);
		anArray.push(((aUnicode >> 6) & 0x3f) | 0x80);
		anArray.push((aUnicode & 0x3f) | 0x80);
	} else {													//	0x00010000 - 0x001fffff -> 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
		anArray.push((aUnicode >> 18) | 0xf0);
		anArray.push(((aUnicode >> 12) & 0x3f) | 0x80);
		anArray.push(((aUnicode >> 6) & 0x3f) | 0x80);
		anArray.push((aUnicode & 0x3f) | 0x80);
	}
}

ByteArray.prefixMatchingBits = function (aValue, bValue) {
	var	result;
	var i,c;
	
	result = 0;

	c = Math.min(aValue.length(), bValue.length());
	i = 0;
	while (i<c && (aValue.byteAtIndex(i) == bValue.byteAtIndex(i))) {
		result += 8;
		i++;
	}

	if (i<c) {
		var	xorValue;
		
		xorValue = (aValue.byteAtIndex(i) ^ bValue.byteAtIndex(i));
		
		if (xorValue >= 128) {
			result += 0;
		} else if (xorValue >= 64) {
			result += 1;
		} else if (xorValue >= 32) {
			result += 2;
		} else if (xorValue >= 16) {
			result += 3;
		} else if (xorValue >= 8) {
			result += 4;
		} else if (xorValue >= 4) {
			result += 5;
		} else if (xorValue >= 2) {
			result += 6;
		} else if (xorValue >= 1) {
			result += 7;
		}
	}

	return result;
};

var ByteArrayIterator = new Class({

	initialize: function(args){
		args = args || {};

		this._byteArray = args.byteArray;
		this._blockSize = args.blockSize;
		this._finalPadding = args.finalPadding || false;
		
		this._currentPosition = 0;
		
		return this;
	},

	'blockSize': function() {
		var result;
		
		result = this._blockSize;
		
		return result;
	},

	'currentPosition': function() {
		var result;
		
		result = this._currentPosition;
		
		return result;
	},

	'byteArray': function() {
		var result;
		
		result = this._byteArray;
		
		return result;
	},
	
	'finalPadding': function() {
		var result;
		
		result = this._finalPadding;
		
		return result;
	},
	
	'nextBlock': function() {
		var result;
		var currentPosition;
		var	byteArrayLength;
		
		currentPosition = this._currentPosition;
		byteArrayLength = this.byteArray().length();
		
		if (currentPosition < byteArrayLength) {
			var i,c;

			c = this.blockSize();
			result = new Array(c);
			for (i=0; i<c; i++) {
				if (currentPosition < byteArrayLength) {
					result[i] = this.byteArray().byteAtIndex(currentPosition);
					currentPosition++;
				} else if (this.finalPadding() == true) {
					result[i] = 0;
				}
			}
			
			this._currentPosition = currentPosition;
		} else {
			result = null;
		}
		
		return result;
	},	

	'nextBlockArray': function() {
		var result;
		var nextBlock;

		nextBlock = this.nextBlock();
		
		if (nextBlock != null) {
			result = new Clipperz.ByteArray(nextBlock);
		} else {
			result = null;
		}
		
		return result;
	}
});
