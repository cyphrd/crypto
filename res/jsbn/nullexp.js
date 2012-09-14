goog.provide('cyphrd.crypto.jsbn.nullexp');

/**
 * A "null" reducer
 *
 * @constructor
 */
cyphrd.crypto.jsbn.nullexp = function() {};

cyphrd.crypto.jsbn.nullexp.prototype.convert = function(x) {
	return x;
};

cyphrd.crypto.jsbn.nullexp.prototype.revert = function(x) {
	return x;
};

cyphrd.crypto.jsbn.nullexp.prototype.mulTo = function(x,y,r) {
	x.multiplyTo(y,r);
};

cyphrd.crypto.jsbn.nullexp.prototype.sqrTo = function(x,r) {
	x.squareTo(r);
};
