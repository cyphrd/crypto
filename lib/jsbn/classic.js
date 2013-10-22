goog.provide('cyphrd.crypto.jsbn.classic');

/**
 * Modular reduction using "classic" algorithm
 *
 * @constructor
 */
cyphrd.crypto.jsbn.classic = function(m) {
  this.m = m;
};

cyphrd.crypto.jsbn.classic.prototype.convert = function(x) {
  if(x.s < 0 || x.compareTo(this.m) >= 0) return x.mod(this.m);
  else return x;
};

cyphrd.crypto.jsbn.classic.prototype.revert = function(x) {
  return x;
};

cyphrd.crypto.jsbn.classic.prototype.reduce = function(x) {
  x.divRemTo(this.m,null,x);
};

cyphrd.crypto.jsbn.classic.prototype.mulTo = function(x,y,r) {
  x.multiplyTo(y,r);
  this.reduce(r);
};

cyphrd.crypto.jsbn.classic.prototype.sqrTo = function(x,r) {
  x.squareTo(r);
  this.reduce(r);
};