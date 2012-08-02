Crypto.PRNG = {};

Crypto.PRNG.EntropyAccumulator = new Class({
	initialize: function(args) {
		args = args || {};

		this._stack = new ByteArray();
		this._maxStackLengthBeforeHashing = args.maxStackLengthBeforeHashing || 256;
		return this;
	},

	'toString': function() {
		return "Crypto.PRNG.EntropyAccumulator";
	},

	'stack': function() {
		return this._stack;
	},
	
	'setStack': function(aValue) {
		this._stack = aValue;
	},

	'resetStack': function() {
		this.stack().reset();
	},
	
	'maxStackLengthBeforeHashing': function() {
		return this._maxStackLengthBeforeHashing;
	},

	'addRandomByte': function(aValue) {
		this.stack().appendByte(aValue);
				
		if (this.stack().length() > this.maxStackLengthBeforeHashing()) {
			this.setStack(Crypto.SHA.sha_d256(this.stack()));
		}
	}
});

Crypto.PRNG.RandomnessSource = new Class({
	Implements: Options,

	options: {
		generator: null,
		sourceId: null,
		boostMode: null
	},

	initialize: function(options) {
		this.setOptions(options);
		this._nextPoolIndex = 0;
		return this;
	},

	'generator': function() {
		return this.options.generator;
	},

	'setGenerator': function(aValue) {
		this.options.generator = aValue;
	},

	'boostMode': function() {
		return this.options.boostMode;
	},
	
	'setBoostMode': function(aValue) {
		this.options.boostMode = aValue;
	},
	
	'sourceId': function() {
		return this.options.sourceId;
	},

	'setSourceId': function(aValue) {
		this.options.sourceId = aValue;
	},
	
	'nextPoolIndex': function() {
		return this._nextPoolIndex;
	},
	
	'incrementNextPoolIndex': function() {
		this._nextPoolIndex = ((this._nextPoolIndex + 1) % this.generator().numberOfEntropyAccumulators());
	},
	
	'updateGeneratorWithValue': function(aRandomValue) {
		if (this.generator() != null) {
			this.generator().addRandomByte(this.sourceId(), this.nextPoolIndex(), aRandomValue);
			this.incrementNextPoolIndex();
		}
	}
});

Crypto.PRNG.TimeRandomnessSource = new Class({
	Extends: Crypto.PRNG.RandomnessSource,
	Implements: Options,

	options: {
		intervalTime: 1000
	},

	initialize: function(options) {
		this.setOptions(options);
		this.parent(options);
		this.collectEntropy();
	},

	'intervalTime': function() {
		return this.options.intervalTime;
	},
	
	'collectEntropy': function() {
		var entropyByte = (Date.now() & 0xff),
			intervalTime = this.intervalTime();
		if (this.boostMode() == true) {
			intervalTime = intervalTime / 9;
		}
		
		this.updateGeneratorWithValue(entropyByte);
		setTimeout(this.collectEntropy.bind(this), intervalTime);
	},
	
	'numberOfRandomBits': function() {
		return 5;
	},
	
	'pollingFrequency': function() {
		return 10;
	}
});

Crypto.PRNG.MouseRandomnessSource = new Class({
	initialize: function(args) {
		args = args || {};

		Crypto.PRNG.RandomnessSource.call(this, args);

		this._numberOfBitsToCollectAtEachEvent = 4;
		this._randomBitsCollector = 0;
		this._numberOfRandomBitsCollected = 0;
		
		MochiKit.Signal.connect(document, 'onmousemove', this, 'collectEntropy');

		return this;
	},

	'numberOfBitsToCollectAtEachEvent': function() {
		return this._numberOfBitsToCollectAtEachEvent;
	},
	
	'randomBitsCollector': function() {
		return this._randomBitsCollector;
	},

	'setRandomBitsCollector': function(aValue) {
		this._randomBitsCollector = aValue;
	},

	'appendRandomBitsToRandomBitsCollector': function(aValue) {
		var collectedBits;
		var numberOfRandomBitsCollected;
		
		numberOfRandomBitsCollected = this.numberOfRandomBitsCollected();
		collectetBits = this.randomBitsCollector() | (aValue << numberOfRandomBitsCollected);
		this.setRandomBitsCollector(collectetBits);
		numberOfRandomBitsCollected += this.numberOfBitsToCollectAtEachEvent();
		
		if (numberOfRandomBitsCollected == 8) {
			this.updateGeneratorWithValue(collectetBits);
			numberOfRandomBitsCollected = 0;
			this.setRandomBitsCollector(0);
		}
		
		this.setNumberOfRandomBitsCollected(numberOfRandomBitsCollected)
	},
	
	'numberOfRandomBitsCollected': function() {
		return this._numberOfRandomBitsCollected;
	},

	'setNumberOfRandomBitsCollected': function(aValue) {
		this._numberOfRandomBitsCollected = aValue;
	},

	'collectEntropy': function(anEvent) {
		var mouseLocation;
		var randomBit;
		var mask;
		
		mask = 0xffffffff >>> (32 - this.numberOfBitsToCollectAtEachEvent());
		
		mouseLocation = anEvent.mouse().client;
		randomBit = ((mouseLocation.x ^ mouseLocation.y) & mask);
		this.appendRandomBitsToRandomBitsCollector(randomBit)
	},
	
	'numberOfRandomBits': function() {
		return 1;
	},
	
	'pollingFrequency': function() {
		return 10;
	}
});

Crypto.PRNG.KeyboardRandomnessSource = new Class({
	initialize: function(args) {
		args = args || {};
		Crypto.PRNG.RandomnessSource.call(this, args);

		this._randomBitsCollector = 0;
		this._numberOfRandomBitsCollected = 0;
		
		MochiKit.Signal.connect(document, 'onkeypress', this, 'collectEntropy');

		return this;
	},

	'randomBitsCollector': function() {
		return this._randomBitsCollector;
	},

	'setRandomBitsCollector': function(aValue) {
		this._randomBitsCollector = aValue;
	},

	'appendRandomBitToRandomBitsCollector': function(aValue) {
		var collectedBits;
		var numberOfRandomBitsCollected;
		
		numberOfRandomBitsCollected = this.numberOfRandomBitsCollected();
		collectetBits = this.randomBitsCollector() | (aValue << numberOfRandomBitsCollected);
		this.setRandomBitsCollector(collectetBits);
		numberOfRandomBitsCollected ++;
		
		if (numberOfRandomBitsCollected == 8) {
			this.updateGeneratorWithValue(collectetBits);
			numberOfRandomBitsCollected = 0;
			this.setRandomBitsCollector(0);
		}
		
		this.setNumberOfRandomBitsCollected(numberOfRandomBitsCollected)
	},
	
	'numberOfRandomBitsCollected': function() {
		return this._numberOfRandomBitsCollected;
	},

	'setNumberOfRandomBitsCollected': function(aValue) {
		this._numberOfRandomBitsCollected = aValue;
	},

	'numberOfRandomBits': function() {
		return 1;
	},
	
	'pollingFrequency': function() {
		return 10;
	}
});

Crypto.PRNG.Fortuna = new Class({
	initialize: function(args) {
		var	i,c;
		
		args = args || {};

		this._key = args.seed || null;
		if (this._key == null) {
			this._counter = 0;
			this._key = new ByteArray();
		} else {
			this._counter = 1;
		}
		
		this._aesKey = null;
		
		this._firstPoolReseedLevel = args.firstPoolReseedLevel || 32 || 64;
		this._numberOfEntropyAccumulators = args.numberOfEntropyAccumulators || 32;
		
		this._accumulators = [];
		c = this.numberOfEntropyAccumulators();
		for (i=0; i<c; i++) {
			this._accumulators.push(new Crypto.PRNG.EntropyAccumulator());
		}

		this._randomnessSources = [];
		this._reseedCounter = 0;
		
		return this;
	},

	'key': function() {
		return this._key;
	},

	'setKey': function(aValue) {
		this._key = aValue;
		this._aesKey = null;
	},
	
	'aesKey': function() {
		if (this._aesKey == null) {
			this._aesKey = new Crypto.AES.Key({key:this.key()});
		}
		
		return this._aesKey;
	},
	
	'accumulators': function() {
		return this._accumulators;
	},
	
	'firstPoolReseedLevel': function() {
		return this._firstPoolReseedLevel;
	},
	
	'reseedCounter': function() {
		return this._reseedCounter;
	},

	'incrementReseedCounter': function() {
		this._reseedCounter = this._reseedCounter +1;
	},

	'reseed': function() {
		var	newKeySeed;
		var reseedCounter;
		var	reseedCounterMask;
		var i, c;
		
		newKeySeed = this.key();
		this.incrementReseedCounter();
		reseedCounter = this.reseedCounter();
		
		c = this.numberOfEntropyAccumulators();
		reseedCounterMask = 0xffffffff >>> (32 - c);
		for (i=0; i<c; i++) {
			if ((i == 0) || ((reseedCounter & (reseedCounterMask >>> (c - i))) == 0)) {
				newKeySeed.appendBlock(this.accumulators()[i].stack());
				this.accumulators()[i].resetStack();
			} 
		}
		
		if (reseedCounter == 1) {
			c = this.randomnessSources().length;
			for (i=0; i<c; i++) {
				this.randomnessSources()[i].setBoostMode(false);
			}
		}
		
		this.setKey(Crypto.SHA.sha_d256(newKeySeed));
		if (reseedCounter == 1) {
			Console.log("### PRNG.readyToGenerateRandomBytes");
			MochiKit.Signal.signal(this, 'readyToGenerateRandomBytes');
		}
		MochiKit.Signal.signal(this, 'reseeded');
	},
	
	'isReadyToGenerateRandomValues': function() {
		return this.reseedCounter() != 0;
	},
	
	'entropyLevel': function() {
		return this.accumulators()[0].stack().length() + (this.reseedCounter() * this.firstPoolReseedLevel());
	},
	
	'counter': function() {
		return this._counter;
	},
	
	'incrementCounter': function() {
		this._counter += 1;
	},
	
	'counterBlock': function() {
		return new ByteArray().appendWords(this.counter(), 0, 0, 0);
	},

	'getRandomBlock': function() {
		var result;

		result = new ByteArray(Crypto.AES.encryptBlock(this.aesKey(), this.counterBlock().arrayValues()));
		this.incrementCounter();
		
		return result;
	},
	
	'getRandomBytes': function(aSize) {
		var result;

		if (this.isReadyToGenerateRandomValues()) {
			var i,c;
			var newKey;
			
			result = new ByteArray();
		
			c = Math.ceil(aSize / (128 / 8));
			for (i=0; i<c; i++) {
				result.appendBlock(this.getRandomBlock());
			}

			if (result.length() != aSize) {
				result = result.split(0, aSize);
			}
			
			newKey = this.getRandomBlock().appendBlock(this.getRandomBlock());
			this.setKey(newKey);
		} else {
			Console.warn("Fortuna generator has not enough entropy, yet!");
			throw 'NotEnoughEntropy';
		}

		return result;
	},

	'addRandomByte': function(aSourceId, aPoolId, aRandomValue) {
		var	selectedAccumulator;

		selectedAccumulator = this.accumulators()[aPoolId];
		selectedAccumulator.addRandomByte(aRandomValue);

		if (aPoolId == 0) {
			MochiKit.Signal.signal(this, 'addedRandomByte')
			if (selectedAccumulator.stack().length() > this.firstPoolReseedLevel()) {
				this.reseed();
			}
		}
	},

	'numberOfEntropyAccumulators': function() {
		return this._numberOfEntropyAccumulators;
	},

	'randomnessSources': function() {
		return this._randomnessSources;
	},
	
	'addRandomnessSource': function(aRandomnessSource) {
		aRandomnessSource.setGenerator(this);
		aRandomnessSource.setSourceId(this.randomnessSources().length);
		this.randomnessSources().push(aRandomnessSource);
		
		if (this.isReadyToGenerateRandomValues() == false) {
			aRandomnessSource.setBoostMode(true);
		}
	},

	'deferredEntropyCollection': function(aValue) {
		var result;

		if (this.isReadyToGenerateRandomValues()) {
			result = aValue;
		} else {
			var deferredResult;

			deferredResult = new Async.Deferred("PRNG.deferredEntropyCollection");
			deferredResult.addCallback(MochiKit.Base.partial(MochiKit.Async.succeed, aValue));
			MochiKit.Signal.connect(this,
				'readyToGenerateRandomBytes',
				deferredResult,
				'callback'
			);
									
			result = deferredResult;
		}

		return result;
	},
	
	'fastEntropyAccumulationForTestingPurpose': function() {
		while (! this.isReadyToGenerateRandomValues()) {
			this.addRandomByte(Math.floor(Math.random() * 32), Math.floor(Math.random() * 32), Math.floor(Math.random() * 256));
		}
	},
	
	'dump': function(appendToDoc) {
		var tbl;
		var i,c;
		
		tbl = document.createElement("table");
		tbl.border = 0;
		with (tbl.style) {
			border = "1px solid lightgrey";
			fontFamily = 'Helvetica, Arial, sans-serif';
			fontSize = '8pt';
			//borderCollapse = "collapse";
		}
		var hdr = tbl.createTHead();
		var hdrtr = hdr.insertRow(0);
		// document.createElement("tr");
		{
			var ntd;
			
			ntd = hdrtr.insertCell(0);
			ntd.style.borderBottom = "1px solid lightgrey";
			ntd.style.borderRight = "1px solid lightgrey";
			ntd.appendChild(document.createTextNode("#"));

			ntd = hdrtr.insertCell(1);
			ntd.style.borderBottom = "1px solid lightgrey";
			ntd.style.borderRight = "1px solid lightgrey";
			ntd.appendChild(document.createTextNode("s"));

			ntd = hdrtr.insertCell(2);
			ntd.colSpan = this.firstPoolReseedLevel();
			ntd.style.borderBottom = "1px solid lightgrey";
			ntd.style.borderRight = "1px solid lightgrey";
			ntd.appendChild(document.createTextNode("base values"));
			
			ntd = hdrtr.insertCell(3);
			ntd.colSpan = 20;
			ntd.style.borderBottom = "1px solid lightgrey";
			ntd.appendChild(document.createTextNode("extra values"));

		}

		c = this.accumulators().length;
		for (i=0; i<c ; i++) {
			var	currentAccumulator;
			var bdytr;
			var bdytd;
			var ii, cc;

			currentAccumulator = this.accumulators()[i]
			
			bdytr = tbl.insertRow(true);
			
			bdytd = bdytr.insertCell(0);
			bdytd.style.borderRight = "1px solid lightgrey";
			bdytd.style.color = "lightgrey";
			bdytd.appendChild(document.createTextNode("" + i));

			bdytd = bdytr.insertCell(1);
			bdytd.style.borderRight = "1px solid lightgrey";
			bdytd.style.color = "gray";
			bdytd.appendChild(document.createTextNode("" + currentAccumulator.stack().length()));


			cc = Math.max(currentAccumulator.stack().length(), this.firstPoolReseedLevel());
			for (ii=0; ii<cc; ii++) {
				var cellText;
				
				bdytd = bdytr.insertCell(ii + 2);
				
				if (ii < currentAccumulator.stack().length()) {
					cellText = ByteArray.byteToHex(currentAccumulator.stack().byteAtIndex(ii));
				} else {
					cellText = "_";
				}
				
				if (ii == (this.firstPoolReseedLevel() - 1)) {
					bdytd.style.borderRight = "1px solid lightgrey";
				}
				
				bdytd.appendChild(document.createTextNode(cellText));
			}
			
		}
		

		if (appendToDoc) {
			var ne = document.createElement("div");
			ne.id = "entropyGeneratorStatus";
			with (ne.style) {
				fontFamily = "Courier New, monospace";
				fontSize = "12px";
				lineHeight = "16px";
				borderTop = "1px solid black";
				padding = "10px";
			}
			if (document.getElementById(ne.id)) {
				MochiKit.DOM.swapDOM(ne.id, ne);
			} else {
				document.body.appendChild(ne);
			}
			ne.appendChild(tbl);
		}

		return tbl;
	}
});

Crypto.PRNG.Random = new Class({
	'getRandomBytes': function(aSize) {
		var	result;
		var i,c;
		
		result = new ByteArray();
		c = aSize || 1;
		for (i=0; i<c; i++) {
			result.appendByte((Math.random()*255) & 0xff);
		}
		
		return result;
	}
});

_clipperz_crypt_prng_defaultPRNG = null;

Crypto.PRNG.defaultRandomGenerator = function() {
	if (_clipperz_crypt_prng_defaultPRNG == null) {
		_clipperz_crypt_prng_defaultPRNG = new Crypto.PRNG.Fortuna();

		{
			var newRandomnessSource;
		
			newRandomnessSource = new Crypto.PRNG.TimeRandomnessSource({intervalTime:111});
			_clipperz_crypt_prng_defaultPRNG.addRandomnessSource(newRandomnessSource);
		}

		{
			var	newRandomnessSource;
			
			newRandomnessSource = new Crypto.PRNG.MouseRandomnessSource();
			_clipperz_crypt_prng_defaultPRNG.addRandomnessSource(newRandomnessSource);
		}

		{
			var	newRandomnessSource;
			
			newRandomnessSource = new Crypto.PRNG.KeyboardRandomnessSource();
			_clipperz_crypt_prng_defaultPRNG.addRandomnessSource(newRandomnessSource);
		}
	}

	return _clipperz_crypt_prng_defaultPRNG;
};

//window.addEvent('domready', Crypto.PRNG.defaultRandomGenerator);