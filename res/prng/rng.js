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

goog.provide('cyphrd.crypto.random.secure');

// prng4.js - uses Arcfour as a PRNG

function Arcfour() {
	this.i = 0;
	this.j = 0;
	this.S = [];
}

// Initialize arcfour context from key, an array of ints, each from [0..255]
Arcfour.prototype.init = function(key) {
	var i, j, t;
	for(i = 0; i < 256; ++i)
	this.S[i] = i;
	j = 0;
	for(i = 0; i < 256; ++i) {
	j = (j + this.S[i] + key[i % key.length]) & 255;
	t = this.S[i];
	this.S[i] = this.S[j];
	this.S[j] = t;
	}
	this.i = 0;
	this.j = 0;
}

Arcfour.prototype.next = function() {
	var t;
	this.i = (this.i + 1) & 255;
	this.j = (this.j + this.S[this.i]) & 255;
	t = this.S[this.i];
	this.S[this.i] = this.S[this.j];
	this.S[this.j] = t;
	return this.S[(t + this.S[this.i]) & 255];
}

// Pool size must be a multiple of 4 and greater than 32.
// An array of bytes the size of the pool will be passed to init()
var rng_psize = 256;

// Random number generator - requires a PRNG backend, e.g. prng4.js

// For best results, put code like
// <body onClick='rng_seed_time();' onKeyPress='rng_seed_time();'>
// in your main HTML document.

var rng_state;
var rng_pool;
var rng_pptr;

// Mix in a 32-bit integer into the pool
function rng_seed_int(x) {
	rng_pool[rng_pptr++] ^= x & 255;
	rng_pool[rng_pptr++] ^= (x >> 8) & 255;
	rng_pool[rng_pptr++] ^= (x >> 16) & 255;
	rng_pool[rng_pptr++] ^= (x >> 24) & 255;
	if(rng_pptr >= rng_psize) rng_pptr -= rng_psize;
}

// Mix in the current time (w/milliseconds) into the pool
function rng_seed_time() {
	rng_seed_int(+(new Date));
}

// Initialize the pool with junk if needed.
if(rng_pool == null) {
	rng_pool = [];
	rng_pptr = 0;
	var t;

	while(rng_pptr < rng_psize) {
		t = Math.floor(65536 * Math.random());
		rng_pool[rng_pptr++] = t >>> 8;
		rng_pool[rng_pptr++] = t & 255;
	}

	rng_pptr = 0;
	rng_seed_time();
	//rng_seed_int(window.screenX);
	//rng_seed_int(window.screenY);
}

function SecureRandom() {}

SecureRandom.prototype.getByte = function() {
	if(rng_state == null) {
		rng_seed_time();
		rng_state = new Arcfour();
		rng_state.init(rng_pool);
		for(rng_pptr = 0; rng_pptr < rng_pool.length; ++rng_pptr)
			rng_pool[rng_pptr] = 0;
		rng_pptr = 0;
		//rng_pool = null;
	}
	// TODO: allow reseeding after first request
	return rng_state.next();
}

SecureRandom.prototype.nextBytes = function(ba) {
	var i;
	for(i = 0; i < ba.length; ++i) ba[i] = this.getByte();
}