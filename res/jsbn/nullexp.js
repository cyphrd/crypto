goog.provide('cyphrd.jsbn.nullexp');

/**
 * A "null" reducer
 *
 * @constructor
 */
function NullExp() {}

NullExp.prototype.convert = function(x) {
	return x;
};

NullExp.prototype.revert = function(x) {
	return x;
};

NullExp.prototype.mulTo = function(x,y,r) {
	x.multiplyTo(y,r);
};

NullExp.prototype.sqrTo = function(x,r) {
	x.squareTo(r);
};
