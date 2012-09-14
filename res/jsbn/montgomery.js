goog.provide('cyphrd.crypto.jsbn.montgomery');

/**
 * Montgomery reduction
 *
 * @constructor
 */
cyphrd.crypto.jsbn.montgomery = function(m) {
  this.m = m;
  this.mp = m.invDigit();
  this.mpl = this.mp&0x7fff;
  this.mph = this.mp>>15;
  this.um = (1<<(m.DB-15))-1;
  this.mt2 = 2*m.t;
};

// xR mod m
cyphrd.crypto.jsbn.montgomery.prototype.convert = function(x) {
  var r = nbi();
  x.abs().dlShiftTo(this.m.t,r);
  r.divRemTo(this.m,null,r);
  if(x.s < 0 && r.compareTo(BigInteger.ZERO) > 0) this.m.subTo(r,r);
  return r;
};

// x/R mod m
cyphrd.crypto.jsbn.montgomery.prototype.revert = function montRevert(x) {
  var r = nbi();
  x.copyTo(r);
  this.reduce(r);
  return r;
};

// x = x/R mod m (HAC 14.32)
cyphrd.crypto.jsbn.montgomery.prototype.reduce = function(x) {
  while(x.t <= this.mt2)  // pad x so am has enough room later
    x[x.t++] = 0;
  for(var i = 0; i < this.m.t; ++i) {
    // faster way of calculating u0 = x[i]*mp mod DV
    var j = x[i]&0x7fff;
    var u0 = (j*this.mpl+(((j*this.mph+(x[i]>>15)*this.mpl)&this.um)<<15))&x.DM;
    // use am to combine the multiply-shift-add into one call
    j = i+this.m.t;
    x[j] += this.m.am(0,u0,x,i,0,this.m.t);
    // propagate carry
    while(x[j] >= x.DV) { x[j] -= x.DV; x[++j]++; }
  }
  x.clamp();
  x.drShiftTo(this.m.t,x);
  if(x.compareTo(this.m) >= 0) x.subTo(this.m,x);
};

// r = "xy/R mod m"; x,y != r
cyphrd.crypto.jsbn.montgomery.prototype.mulTo = function(x,y,r) {
  x.multiplyTo(y,r);
  this.reduce(r);
};

// r = "x^2/R mod m"; x != r
cyphrd.crypto.jsbn.montgomery.prototype.sqrTo = function(x,r) {
  x.squareTo(r);
  this.reduce(r);
};