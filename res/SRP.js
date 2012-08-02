/**
 * Crypto.SRP
 *
 * SRP, short for Secure Remote Password Protocol,
 * is a form to check a password without ever
 * sending the entire password to the remove server.
 * 
 * This allows Passwords.cc to verify the correct
 * encryption key without risking the transfer of
 * it to our server, and without attemptint to
 * forcible decrypt data with the wrong key to
 * test its validity.
 *
 * --
 *  Code based off Stanford's original SRP
 *  Authencation project.
 *
 *  This software incorporates components derived from the
 *  Secure Remote Password JavaScript demo developed by
 *  Tom Wu (tjw@CS.Stanford.EDU).
 *
 *  @url http://srp.stanford.edu/
 *  @license http://srp.stanford.edu/license.txt
 */

var srp_N = null;
var srp_Nstr = "115b8b692e0e045692cf280b436735c77a5a9e8a9e7ed56c965f87db5b2a2ece3";
var srp_g = null;
var srp_k = null;
var srp_a = null;
var srp_A = null;
var srp_Astr = null;
var srp_b = null;
var srp_B = null;
var srp_Bstr = null;
var srp_I = null;
var srp_u = null;
var srp_p = null;
var srp_x = null;
var srp_S = null;
var srp_K = null;
var srp_M = null;
var srp_M2 = null;
var xhr;
var rng;

var srp_url = window.location.protocol+"//"+window.location.host+"/srp/";

function srp_register(){
    srp_N = new BigInteger(srp_Nstr, 16); 
    srp_g = new BigInteger("2");
    srp_k = new BigInteger("c46d46600d87fef149bd79b81119842f3c20241fda67d06ef412d8f6d9479c58", 16);
    srp_I = document.getElementById("srp_username").value;
    srp_register_salt(srp_I);
    return false;
};

function srp_register_salt(I){
    new Request.JSON({
    	url: srp_url + "register/salt/",
    	method: 'POSt',
    	data: {I: I},
    	onSuccess: function(json){
    		if (json.ok && json.salt) {
    			srp_x = srp_calculate_x(s);
			    v = srp_g.modPow(srp_x, srp_N);
			    srp_register_send_verifier(v.toString(16));
    		}
    		else {
    			alert(json.error);
    		}
    	}
    }).send();
};

function srp_register_send_verifier(v){
    new Request.JSON({
        url: srp_url+ "register/user/",
        data: {v: v},
        method: 'POST',
        onSuccess: function(json){
        	if(json.ok)
        		srp_identify();
        }
    }).send();
};

function srp_identify(){
    srp_N = new BigInteger(srp_Nstr, 16);
    srp_g = new BigInteger("2");
    srp_k = new BigInteger("c46d46600d87fef149bd79b81119842f3c20241fda67d06ef412d8f6d9479c58", 16); 
    rng = new SecureRandom();
    srp_a = new BigInteger(32, rng);
    // A = g**a % N
    srp_A = srp_g.modPow(srp_a, srp_N); 
    srp_I = document.getElementById("srp_username").value;

    srp_Astr = srp_A.toString(16);
    // C -> S: A | I
    srp_send_identity(srp_Astr, srp_I);
    return false;
};

function srp_send_identity(Astr, I){
    new Request.JSON({
    	url: srp_url + "handshake/",
        data: {I: I, A: Astr},
        method: 'POST',
        onSuccess: function(json){
        	if(json.r){
        		srp_calculations(json.s, json.B);
        	} else {
        		srp_identify();
        	}
        }
    }).send();
};

function srp_calculate_x(s){
    var p = document.getElementById("srp_password").value;
    return new BigInteger(Crypto.SHA256.hex(s + Crypto.SHA256.hex(srp_I + ":" + p)), 16);
};

function srp_calculations(s, B){
	//S -> C: s | B
	srp_B = new BigInteger(B, 16);
	srp_Bstr = B;
	// u = H(A,B)
	srp_u = new BigInteger(Crypto.SHA256.hex(srp_Astr + srp_Bstr), 16);
	// x = H(s, H(I:p))
	srp_x = srp_calculate_x(s);
	//S = (B - kg^x) ^ (a + ux)
	var kgx = srp_k.multiply(srp_g.modPow(srp_x, srp_N));
	var aux = srp_a.add(srp_u.multiply(srp_x));
	srp_S = srp_B.subtract(kgx).modPow(aux, srp_N);
	// M = H(H(N) xor H(g), H(I), s, A, B, K)
	var Mstr = srp_A.toString(16) + srp_B.toString(16) + srp_S.toString(16);
	srp_M = Crypto.SHA256.hex(Mstr);
	srp_send_hash(srp_M);
	//M2 = H(A, M, K)
	srp_M2 = Crypto.SHA256.hex(srp_A.toString(16) + srp_M + srp_S.toString(16));
};


function srp_send_hash(M){
	new Request.JSON({
		url: srp_url+ "authenticate/",
		data: {'M': M},
		method: 'POST',
		onSuccess: function(json){
			if(json.M == srp_M2)
		        srp_success();
		    else
		        alert("Server key does not match");
		}
	}).send();
};