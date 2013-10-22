var assert = require("assert")
var crypto = require('..');

describe("aes", function()
{
	describe("FIPS Verification", function()
	{
		it("128-bit", function()
		{
			crypto.aes.size(128);
			var f128block = crypto.aes.h2a("00112233445566778899aabbccddeeff");
			var f128ciph = crypto.aes.h2a("69c4e0d86a7b0430d8cdb78070b4c55a");
			var f128key = crypto.aes.expandKey(crypto.aes.h2a("000102030405060708090a0b0c0d0e0f"));

			assert.equal(
				crypto.aes.encryptBlock(f128block, f128key).toString(),
				f128ciph.toString()
			);

			assert.equal(
				crypto.aes.decryptBlock(f128ciph, f128key).toString(),
				f128block.toString()
			);
		});

		it("192-bit", function()
		{
			crypto.aes.size(192);
			var f192block = crypto.aes.h2a("00112233445566778899aabbccddeeff");
			var f192ciph = crypto.aes.h2a("dda97ca4864cdfe06eaf70a0ec0d7191");
			var f192key = crypto.aes.expandKey(crypto.aes.h2a("000102030405060708090a0b0c0d0e0f1011121314151617"));

			assert.equal(
				crypto.aes.encryptBlock(f192block, f192key).toString(),
				f192ciph.toString()
			);

			assert.equal(
				crypto.aes.decryptBlock(f192ciph, f192key).toString(),
				f192block.toString()
			);
		});

		it("256-bit", function()
		{
			crypto.aes.size(256);
			var f256block = crypto.aes.h2a("00112233445566778899aabbccddeeff");
			var f256ciph = crypto.aes.h2a("8ea2b7ca516745bfeafc49904b496089");
			var f256key = crypto.aes.expandKey(crypto.aes.h2a("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
			
			assert.equal(
				crypto.aes.encryptBlock(f256block, f256key).toString(),
				f256ciph.toString()
			);

			assert.equal(
				crypto.aes.decryptBlock(f256ciph, f256key).toString(),
				f256block.toString()
			);
		});
	});

	describe("OpenSSL Compatibility", function()
	{
		it("128-bit encryption", function()
		{
			// echo -n "secretsecretsecret" | openssl enc -e -a -aes-128-cbc -K 5e884898da28047151d0e56f8dc62927 -iv 6bbda7892ad344e06c31e64564a69a9a
			// 4j+jnKTSsTBVUJ9MuV8hFEHuxdyT065rYbUqo0gJo1I=   Hex: e23fa39ca4d2b13055509f4cb95f211441eec5dc93d3ae6b61b52aa34809a352
			crypto.aes.size(128);        
			var key = crypto.aes.h2a("5e884898da28047151d0e56f8dc62927"); //sha256 of "password"
			var iv = crypto.aes.h2a("6bbda7892ad344e06c31e64564a69a9a");
			var plaintext = crypto.aes.s2a("secretsecretsecret");
			var openssl = "4j+jnKTSsTBVUJ9MuV8hFEHuxdyT065rYbUqo0gJo1I=\n"
			var enc = crypto.aes.rawEncrypt(plaintext, key, iv);

			assert.equal(
				crypto.b64.encodeByteArray(enc),
				openssl
			);
		});
		
		it("192-bit encryption", function()
		{
			// echo -n "secretsecretsecret" | openssl enc -e -a -aes-192-cbc -K 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd6 -iv 6bbda7892ad344e06c31e64564a69a9a
			// g1D8nfnp31TH8jaV3304KP23i6aQhSaU3gubyGtV6WE=                Hex: 8350fc9df9e9df54c7f23695df7d3828fdb78ba690852694de0b9bc86b55e961
			crypto.aes.size(192);        
			var password = crypto.aes.h2a("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd6"); //sha256 of "password"
			var iv = crypto.aes.h2a("6bbda7892ad344e06c31e64564a69a9a");
			var plaintext = crypto.aes.s2a("secretsecretsecret");
			var openssl = "g1D8nfnp31TH8jaV3304KP23i6aQhSaU3gubyGtV6WE=\n";
			var enc = crypto.aes.rawEncrypt(plaintext, password, iv);

			assert.equal(
				crypto.b64.encodeByteArray(enc),
				openssl
			);
		});

		it("256-bit encryption", function()
		{
			// echo -n "secretsecretsecret" | openssl enc -e -a -aes-256-cbc -K 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 -iv 6bbda7892ad344e06c31e64564a69a9a
			// XUfDIa3urWyzHC1bmfmSQJjaTEXPmKkQYvbCnYd6gFY=                Hex: 5d47c321adeead6cb31c2d5b99f9924098da4c45cf98a91062f6c29d877a8056
			crypto.aes.size(256);        
			var password = crypto.aes.h2a("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"); //sha256 of "password"
			var iv = crypto.aes.h2a("6bbda7892ad344e06c31e64564a69a9a");
			var plaintext = crypto.aes.s2a("secretsecretsecret");
			var openssl = "XUfDIa3urWyzHC1bmfmSQJjaTEXPmKkQYvbCnYd6gFY=\n";
			var enc = crypto.aes.rawEncrypt(plaintext, password, iv);
			
			assert.equal(
				crypto.b64.encodeByteArray(enc),
				openssl
			);
		});
		
		it("128-bit decryption", function()
		{
			crypto.aes.size(128);
			assert.equal(
				crypto.aes.dec("U2FsdGVkX19SF/vHKUf1zS4SMlbROLLCRiyprMJuQ+1nzQJyatGmJhC9xJ6Od+vcZtgZyurEqeEkna1Kj4gqdw==", "pass"),
				"This was decrypted successfully\n"
			);
		});

		it("192-bit decryption", function()
		{
			crypto.aes.size(192);
			assert.equal(
				crypto.aes.dec("U2FsdGVkX18EDbSr5+mGnFZRUwSTISFzadp7wsC/kTgtco+fQ4hMMrJ1zpePN6sicBnAOaC+p/vCmgb3zBc7Ag==", "pass"),
				"This was decrypted successfully\n"
			);
		});

		it("256-bit decryption", function()
		{
			crypto.aes.size(256);
			assert.equal(
				crypto.aes.dec("U2FsdGVkX1+f4uMd56OoVkwmaLStldQEHRNSGa1gRVF0XUvNNIr4Vg1PWa+0HHpiTRmvKXFSY90SrJea4Cb+zA==", "pass"),
				"This was decrypted successfully\n"
			);
		});
	});

	describe("PBE Testing", function()
	{
		it("128-bit", function()
		{
			crypto.aes.size(128);
			var password = crypto.aes.s2a("mumstheword");
			var salt = crypto.aes.h2a("C3CA5EE98B8F1FC5");
			var key = crypto.aes.h2a("1D189274EB848A8CD1F3D029030E0E5A");
			var iv = crypto.aes.h2a("ED562A01653B3973C4507CF2B97F3641");
			var pbe = crypto.aes.openSSLKey(password, salt);
			crypto.aes.a2h(pbe.key);
			crypto.aes.a2h(pbe.iv);
			
			assert.equal(
				crypto.aes.a2h(pbe.key),
				crypto.aes.a2h(key)
			);

			assert.equal(
				crypto.aes.a2h(pbe.iv),
				crypto.aes.a2h(iv)
			);
		});

		it("192-bit", function()
		{
			crypto.aes.size(192);
			var password = crypto.aes.s2a("mumstheword")
			var salt = crypto.aes.h2a("6C96EB8089668585")
			var key = crypto.aes.h2a("1A5EC3EB94BF5A675B2CE79E30D84EA8E68936A7E17FFCC7")
			var iv = crypto.aes.h2a("6E82636638721A2C7B92FB6EE007C3BC")
			var pbe = crypto.aes.openSSLKey(password, salt);
			crypto.aes.a2h(pbe.key);
			crypto.aes.a2h(pbe.iv);
			
			assert.equal(
				crypto.aes.a2h(pbe.key),
				crypto.aes.a2h(key)
			);

			assert.equal(
				crypto.aes.a2h(pbe.iv),
				crypto.aes.a2h(iv)
			);
		});

		it("256-bit", function()
		{
			crypto.aes.size(256);
			var password = crypto.aes.s2a("mumstheword")
			var salt = crypto.aes.h2a("5F934E4432AEB8B3")
			var key = crypto.aes.h2a("3d6b59e8c5623ce4ff7c165995b209e7f03461ec057ca33a5cd1559d01e5682b")
			var iv = crypto.aes.h2a("5be59eadbed053db61bd9e413fb8b7d5")
			var pbe = crypto.aes.openSSLKey(password, salt);
			crypto.aes.a2h(pbe.key);
			crypto.aes.a2h(pbe.iv);

			assert.equal(
				crypto.aes.a2h(pbe.key),
				crypto.aes.a2h(key)
			);

			assert.equal(
				crypto.aes.a2h(pbe.iv),
				crypto.aes.a2h(iv)
			);
		});

		//crypto.aes.rawDecrypt("dd52055f3e2348a864115fd06979e6c8", "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", "6bbda7892ad344e06c31e64564a69a9a")
		// "f4XTQBzF6h+B0T+P9bfqUKHO1nhsZAmYbmP55VHMmxZqTsx9Nhi0SZVck+0onxmsgAXxaEqyUmztv3726w0Kb03LpfOGszmQOQvwwmkV5goeB1oTKWThz+cIGh4qZcdnc/+Cq0sQ7QFBpkwhaFyFf2z2zDos+2hGr2qs04Jlj8Wx5fQTPWwFnsxKV4+rmqswnWwY6dNjxFi5LQ+aecPw0eDFQzZZuOgsFbreXMYzMWFzyH07khQfA5V45FhgOyq7ulmikUnahjupzlpL4lTaHMx6CU3gZo6E6+Ip5CANFwC0qhPP0Ekhdni5VjYz0Qw7"
		// "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890" 
	});

	describe("UTF-8 Verification", function()
	{
		it("128-bit", function()
		{
			crypto.aes.size(128);
			var chinese = " 版面变化复";
			var enc = crypto.aes.enc(chinese, "secret");
			var dec = crypto.aes.dec(enc, "secret");

			assert.equal(chinese, dec);
		});

		it("192-bit", function()
		{
			crypto.aes.size(192);
			var chinese = " 版面变化复";
			var enc = crypto.aes.enc(chinese, "secret");
			var dec = crypto.aes.dec(enc, "secret");

			assert.equal(chinese, dec);
		});

		it("256-bit", function()
		{
			crypto.aes.size(256);        
			var chinese = " 版面变化复";
			var enc = crypto.aes.enc(chinese, "secret");
			var dec = crypto.aes.dec(enc, "secret");

			assert.equal(chinese, dec);
		});
	});
});