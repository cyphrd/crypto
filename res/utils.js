goog.provide('cyphrd.crypto.utils');

goog.require('cyphrd.crypto.hex');
goog.require('cyphrd.crypto.random.secure');
goog.require('cyphrd.crypto.sha512');

cyphrd.crypto.utils = {
	// inspired by Keepass (http://keepass.info/)
	// Judges a passphrase for it's secureness
	getBits: function(passphrase) {
		if (!passphrase) return 0;
		var cset = [], ci = [0,32,33,47,48,57,58,64,65,90,91,96,97,122,123,126,126,255,256,65535],
			t, ok, factor, df, vdf = [], vcc = [], el=0, bpc, ext, exdf;
		for (var i=0;i<passphrase.length;i++) {
			factor = 1;
			ok = 0;
			t = passphrase.charCodeAt(i);
			for (var j=0;j<ci.length;j+=2) {
				var cc = ci[j];
				if (t>=ci[j] && t<=ci[j+1]) {
					cset[''+j] = ci[j+1]-ci[j];
					ok = 1;
					break;
				}
			}
			if (!ok) cset['x'] = 65280;
			if (i >= 1) {
				df = t - ext;
				if (exdf == df) vdf[df] = 1;
				else {
					vdf[df] = (vdf[df]?vdf[df]:0) + 1;
					factor /= vdf[df];
				}
			}
			if (!vcc[t]) {
				vcc[t] = 1;
				el += factor;
			}
			else el += factor * (1 / ++vcc[t]);
			exdf = df;
			ext = t;
		}
		var tot = 0;
		for (var i in cset) if (!isNaN(parseInt(i,10))) tot += cset[i];
		if (!tot) return 0;
		return Math.ceil(el * Math.log(tot) / Math.log(2));
	},

	charMatrix: {
		lcase: [97,122],
		ucase: [65,90],
		nums: [48,57],
		symb: [33,33,35,47,58,64,91,96,123,126],
		space: [161,254]
	},

	/**
	 * @param {number} n Length
	 * @param {Object=} chars Options for password generation
	 */
	generatePassword: function(n, chars) {
		var str = '';

		if (chars === undefined) {
			chars = {
				lcase: 1,
				ucase: 1,
				nums: 1,
				symb: 1,
				space: 1 // most of the time spaces don't work
			};
		}

		for (var j in chars) {
			if (!chars[j]) continue;
			var M = cyphrd.crypto.utils.charMatrix[j];
			for (var u=0;u<M.length;u+=2) {
				for (var y=M[u];y<=M[u+1];y++) {
					str += String.fromCharCode(y);
				}
			}
		}

		var pass = '';
		if (str) {
			var l = str.length, p = 0;
			for (p=0; p<n;) {
				var v = Math.floor(Math.random() * l);
				if (v == l) continue;
				var c = str.substring(v,v+1);
				pass += c;
				p++;
			}
		}
		return pass;
	},

	gemerateSimplePassword: function(n) {
		return cyphrd.crypto.utils.generatePassword(n || 16, {
			lcase: 1,
			ucase: 1,
			nums: 1
		});
	},

	// generateSalt: function(){
	// 	var i, j, k = "";

	// 	Crypto.Entropy.addTime();
	// 	var seed = Crypto.Entropy.createKey();
	//     var prng = new AESprng(seed);

	//     // Hexadecimal key
	//     var hexDigits = "0123456789ABCDEF";

	//     for (i = 0; i < 64; i++) {
	//     	k += hexDigits.charAt(prng.nextInt(15));
	//     }

	// 	return k;
	// },

	/**
	 * @param {...(Array)} var_args
	 */
	meld: function(var_args) {
		var merged = "",
			// merged = [],
			index = 0,
			cont, i, A;

		do {
			cont = false;
			for (i = 0; i < arguments.length; i++) {
				A = arguments[i];
				if (index < A.length) {
					cont = true;
					// merged.push(A[index]);
					merged += A[index];
				}
			}
			index++;
		} while (cont);

		return merged;
	},

	generateKey: function() {
		var salt = cyphrd.crypto.utils.generatePassword(512),
			x = new Array(256),
			rng = new SecureRandom();

		rng.nextBytes(x);

		var key = '',
			digits = ['0', '1', '2', '3', '4','5','6','7','8','9','a','b','c','d','e','f'];

		for (var idx = 0; idx < x.length; ++idx) {
			/** @type {string} */ var b = x[idx]; // should be a "byte"
			key += digits[(b&0xf0) >> 4];
			key += digits[b&0x0f];
		}

		var result = cyphrd.crypto.utils.meld(key, salt);

		return '' +
		cyphrd.crypto.sha512.hex(result.substr(0, result.length/2)) +
		cyphrd.crypto.sha512.hex(result.substr(result.length/2, result.length));
	},

	/**
	 * Utility function
	 * Returns a useless version of a SHA-512 hash/checksum of a string.
	 * The uselessness makes rainbow tables pretty useless, as it results in a lot of
	 * original strings matching the resulting useless hash. However it's unlikely
	 * the real user will ever mistakenly enter one of these other-matching strings.
	 *
	 * @param {string} str String to hash.
	 * @param {boolean=} nohex If true will return decoded hex version.
	 * @param {boolean=} full If false it will only return a few of the characters of the hash.
	 *
	 * @return {string} A hashed version of string.
	 */
	hashx: function(str, nohex, full) {
		var s = cyphrd.crypto.sha512.hex(str),
			ss = '';

		if (!full) {
			for (var j=0; j<s.length; j+=4) {
				ss += s.substring(j, j+1);
			}
		}

		else {
			ss = s;
		}

		return nohex ? cyphrd.crypto.hex.decode(ss) : ss;
	},

	hash: function(str){
		return cyphrd.crypto.utils.hashx(str + cyphrd.crypto.utils.hashx(str, true, true));
	}
};
