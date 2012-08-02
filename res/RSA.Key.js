Crypto.RSAKey = function(){
	this.n = null;
	this.e = 0;
	this.d = null;
	this.p = null;
	this.q = null;
	this.dmp1 = null;
	this.dmq1 = null;
	this.coeff = null;
};

// Generate a new random private key B bits long, using public expt E
Crypto.RSAKey.prototype.generate = function (B,E) {
	var rng = new SecureRandom();
	var qs = B>>1;
	this.e = parseInt(E,16);
	var ee = new BigInteger(E,16);
	for(;;) {
		for(;;) {
			this.p = new BigInteger(B-qs,1,rng);
			if(this.p.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) == 0 && this.p.isProbablePrime(10)) break;
		}
		for(;;) {
			this.q = new BigInteger(qs,1,rng);
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

// Set the public key fields N and e from hex strings
Crypto.RSAKey.prototype.setPublic = function (N,E){
	if(N != null && E != null && N.length > 0 && E.length > 0) {
		this.n = new BigInteger(N,16);
		this.e = parseInt(E,16);
	}
	else
		alert("Invalid RSA public key");
};

// Set the private key fields N, e, and d from hex strings
Crypto.RSAKey.prototype.setPrivate = function (N,E,D) {
	if(N != null && E != null && N.length > 0 && E.length > 0) {
		this.n = new BigInteger(N,16);
		this.e = parseInt(E,16);
		this.d = new BigInteger(D,16);
	}
	else
		alert("Invalid RSA private key");
};

// Set the private key fields N, e, d and CRT params from hex strings
Crypto.RSAKey.prototype.setPrivateEx = function (N,E,D,P,Q,DP,DQ,C) {
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
Crypto.RSAKey.prototype.doPublic = function (x) {
	return x.modPowInt(this.e, this.n);
};

// Perform raw private operation on "x": return x^d (mod n)
Crypto.RSAKey.prototype.doPrivate = function(x) {
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

Crypto.RSAKey.prototype.encrypt = function(text){
	var max = (this.n.bitLength()+7)>>3,
			m = Crypto.RSA.pkcs1pad2(text, max);
	if(m == null) return null;
	var c = this.doPublic(m);
	if(c == null) return null;
	var h = c.toString(16);
	if((h.length & 1) == 0) return h; else return "0" + h;
};

Crypto.RSAKey.prototype.decrypt = function(ctext){
	if (!this.e) return null;
	var c = new BigInteger(ctext, 16);
	var m = this.doPrivate(c);
	if(m == null) return null;
	return Crypto.RSA.pkcs1unpad2(m, (this.n.bitLength()+7)>>3);
};