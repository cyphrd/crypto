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

goog.provide('cyphrd.crypto.rsa');

goog.require('cyphrd.crypto.random.secure');
goog.require('cyphrd.crypto.jsbn');

/**
 * RSA Key and Encryption
 *
 * Code originally by Tom Wu, available at:
 * http://www-cs-students.stanford.edu/~tjw/jsbn/
 *
 * @constructor
 */
cyphrd.crypto.rsa = function() {
	this.n = null;
	this.e = 0;
	this.d = null;
	this.p = null;
	this.q = null;
	this.dmp1 = null;
	this.dmq1 = null;
	this.coeff = null;
};

/**
 * Generate a new random private key B bits long, using public expt E
 *
 * @param {number} B bitlength (1024, 512, etc).
 * @param {string} E Exponent (10001, 3, etc).
 */
cyphrd.crypto.rsa.prototype.generate = function(B, E) {
	var rng = new SecureRandom();
	var qs = B>>1;
	this.e = parseInt(E,16);
	var ee = new BigInteger(E,16);
	for(;;) {
		for(;;) {
			this.p = new BigInteger(B-qs, 1, rng);
			if(this.p.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) == 0 && this.p.isProbablePrime(10)) break;
		}
		for(;;) {
			this.q = new BigInteger(qs, 1, rng);
			if(this.q.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) == 0 && this.q.isProbablePrime(10)) break;
		}
		if(this.p.compareTo(this.q) <= 0) {
			var t = this.p;
			this.p = this.q;
			this.q = t;
		}
		var p1 = this.p.subtract(BigInteger.ONE);
		var q1 = this.q.subtract(BigInteger.ONE);
		var phi = p1.multiply(q1);
		if(phi.gcd(ee).compareTo(BigInteger.ONE) == 0) {
			this.n = this.p.multiply(this.q);
			this.d = ee.modInverse(phi);
			this.dmp1 = this.d.mod(p1);
			this.dmq1 = this.d.mod(q1);
			this.coeff = this.q.modInverse(this.p);
			break;
		}
	}
};

// PKCS#1 (type 2, random) pad input string s to n bytes, and return a bigint
cyphrd.crypto.rsa.pkcs1pad2 = function(s, n) {
	if(n < s.length + 11) {
		throw Error('Message too long for RSA');
	}

	var ba = [],
	i = s.length - 1;
	while(i >= 0 && n > 0) ba[--n] = s.charCodeAt(i--);
	ba[--n] = 0;
	var rng = new SecureRandom(),
	x = [];
	while(n > 2) { // random non-zero pad
		x[0] = 0;
		while(x[0] == 0) rng.nextBytes(x);
		ba[--n] = x[0];
	}
	ba[--n] = 2;
	ba[--n] = 0;
	return new BigInteger(ba);
};

// Undo PKCS#1 (type 2, random) padding and, if valid, return the plaintext
cyphrd.crypto.rsa.pkcs1unpad2 = function(d, n) {
	var b = d.toByteArray();
	var i = 0;
	while(i < b.length && b[i] == 0) ++i;
	if(b.length-i != n-1 || b[i] != 2)
		return null;
	++i;
	while(b[i] != 0)
		if(++i >= b.length) return null;
	var ret = '';
	while(++i < b.length)
		ret += String.fromCharCode(b[i]);
	return ret;
};

// Set the public key fields N and e from hex strings
cyphrd.crypto.rsa.prototype.setPublic = function(N, E){
	if(N != null && E != null && N.length > 0 && E.length > 0) {
		this.n = new BigInteger(N,16);
		this.e = parseInt(E,16);
	}
	else
		throw Error('Invalid RSA public key');
};

// Set the private key fields N, e, and d from hex strings
cyphrd.crypto.rsa.prototype.setPrivate = function(N, E, D) {
	if(N != null && E != null && N.length > 0 && E.length > 0) {
		this.n = new BigInteger(N,16);
		this.e = parseInt(E,16);
		this.d = new BigInteger(D,16);
	}
	else
		throw Error('Invalid RSA private key');
};

// Set the private key fields N, e, d and CRT params from hex strings
cyphrd.crypto.rsa.prototype.setPrivateEx = function(N, E, D, P, Q, DP, DQ, C) {
	this.n = N;
	this.e = E;
	this.d = D;
	this.p = P;
	this.q = Q;
	this.dmp1 = DP;
	this.dmq1 = DQ;
	this.coeff = C;
};

// Perform raw public operation on "x": return x^e (mod n)
cyphrd.crypto.rsa.prototype.doPublic = function(x) {
	return x.modPowInt(this.e, this.n);
};

// Perform raw private operation on "x": return x^d (mod n)
cyphrd.crypto.rsa.prototype.doPrivate = function(x) {
	if(this.p == null || this.q == null) {
		return x.modPow(this.d, this.n);
	}

	// TODO: re-calculate any missing CRT params
	var xp = x.mod(this.p).modPow(this.dmp1, this.p);
	var xq = x.mod(this.q).modPow(this.dmq1, this.q);

	while(xp.compareTo(xq) < 0) {
		xp = xp.add(this.p);
	}

	return xp.subtract(xq).multiply(this.coeff).mod(this.p).multiply(this.q).add(xq);
};

cyphrd.crypto.rsa.prototype.encrypt = function(text) {
	var max = (this.n.bitLength()+7)>>3,
		m = cyphrd.crypto.rsa.pkcs1pad2(text, max);

	if(m == null)
		return null;

	var c = this.doPublic(m);
	if(c == null)
		return null;

	var h = c.toString(16);
	if ((h.length & 1) == 0)
		return h;
	else
		return '0' + h;
};

cyphrd.crypto.rsa.prototype.decrypt = function(ctext) {
	if (!this.e) return null;
	var c = new BigInteger(ctext, 16);
	var m = this.doPrivate(c);
	if(m == null) return null;
	return cyphrd.crypto.rsa.pkcs1unpad2(m, (this.n.bitLength()+7)>>3);
};
