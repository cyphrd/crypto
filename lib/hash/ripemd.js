/**
 * Crypto library by Cyphrd
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

/**
 * Original work by Jeremy Lin and Paul Johnston
 * @see http://pajhome.org.uk/crypt/md5
 * @see http://www.ocf.berkeley.edu/~jjlin/jsotp/
 */

var utils = require('./utils');

/*
 * Calculate the RIPE-MD160 of an array of little-endian words, and a bit length.
 */
var rmd160 = function binl_rmd160(x, len) {
  /* append padding */
  x[len >> 5] |= 0x80 << (len % 32);
  x[(((len + 64) >>> 9) << 4) + 14] = len;

  var h0 = 0x67452301;
  var h1 = 0xefcdab89;
  var h2 = 0x98badcfe;
  var h3 = 0x10325476;
  var h4 = 0xc3d2e1f0;

  for (var i = 0; i < x.length; i += 16) {
    var T;
    var A1 = h0, B1 = h1, C1 = h2, D1 = h3, E1 = h4;
    var A2 = h0, B2 = h1, C2 = h2, D2 = h3, E2 = h4;

    for (var j = 0; j <= 79; ++j) {
      T = utils.safeAdd(A1, rmd160_f(j, B1, C1, D1));
      T = utils.safeAdd(T, x[i + rmd160_r1[j]]);
      T = utils.safeAdd(T, rmd160_K1(j));
      T = utils.safeAdd(utils.bit_rol(T, rmd160_s1[j]), E1);

      A1 = E1;
      E1 = D1;
      D1 = utils.bit_rol(C1, 10);
      C1 = B1;
      B1 = T;

      T = utils.safeAdd(A2, rmd160_f(79-j, B2, C2, D2));
      T = utils.safeAdd(T, x[i + rmd160_r2[j]]);
      T = utils.safeAdd(T, rmd160_K2(j));
      T = utils.safeAdd(utils.bit_rol(T, rmd160_s2[j]), E2);
      A2 = E2; E2 = D2; D2 = utils.bit_rol(C2, 10); C2 = B2; B2 = T;
    }

    T = utils.safeAdd(h1, utils.safeAdd(C1, D2));
    h1 = utils.safeAdd(h2, utils.safeAdd(D1, E2));
    h2 = utils.safeAdd(h3, utils.safeAdd(E1, A2));
    h3 = utils.safeAdd(h4, utils.safeAdd(A1, B2));
    h4 = utils.safeAdd(h0, utils.safeAdd(B1, C2));
    h0 = T;
  }

  return [h0, h1, h2, h3, h4];
}

function rmd160_f(j, x, y, z) {
  return ( 0 <= j && j <= 15) ? (x ^ y ^ z) :
         (16 <= j && j <= 31) ? (x & y) | (~x & z) :
         (32 <= j && j <= 47) ? (x | ~y) ^ z :
         (48 <= j && j <= 63) ? (x & z) | (y & ~z) :
         (64 <= j && j <= 79) ? x ^ (y | ~z) :
         "rmd160_f: j out of range";
}

function rmd160_K1(j) {
  return ( 0 <= j && j <= 15) ? 0x00000000 :
         (16 <= j && j <= 31) ? 0x5a827999 :
         (32 <= j && j <= 47) ? 0x6ed9eba1 :
         (48 <= j && j <= 63) ? 0x8f1bbcdc :
         (64 <= j && j <= 79) ? 0xa953fd4e :
         "rmd160_K1: j out of range";
}

function rmd160_K2(j) {
  return ( 0 <= j && j <= 15) ? 0x50a28be6 :
         (16 <= j && j <= 31) ? 0x5c4dd124 :
         (32 <= j && j <= 47) ? 0x6d703ef3 :
         (48 <= j && j <= 63) ? 0x7a6d76e9 :
         (64 <= j && j <= 79) ? 0x00000000 :
         "rmd160_K2: j out of range";
}

var rmd160_r1 = [
   0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
   7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8,
   3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12,
   1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2,
   4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13
];

var rmd160_r2 = [
   5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,
   6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,
  15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,
   8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14,
  12, 15, 10,  4,  1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11
];

var rmd160_s1 = [
  11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,
   7,  6,  8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,
  11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,
  11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12,
   9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6
];

var rmd160_s2 = [
   8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,
   9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,
   9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,
  15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8,
   8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11
];

module.exports = require('./wrapper')(rmd160, {
  endian: 'little',
  ipadOffset: 512,
  opadOffset: 160
});
