Crypto.Tests = {

	// Will be a hash of
	// { algorithm: { 'test': function() } }
	TestsRegister: {},
	
	register: function(algorithm, tests){
		Crypto.Tests.TestsRegister[algorithm] = tests;
	},

	perform: function(name){
		if (name && Crypto.Tests.TestsRegister[name])
			return Crypto.Tests.TestsRegister[name]();
		else if (name)
			return null;
		else {
			var results = {};

			$each(Crypto.Tests.TestsRegister, function(tests, algorithm){
				results[algorithm] = {};

				$each(tests, function(func, name){
					try {
						results[algorithm][name] = func();
					}
					catch (e) {
						results[algorithm][name] = [e, e.stack.split("\n")];
					}

					if (results[algorithm][name] !== true)
						Console.log('Test Failed', algorithm, name, results[algorithm][name]);
				}.bind(results));
			}.bind(results));

			return results;
		}
	}

};