goog.provide('cyphrd.crypto.passphrases');
goog.provide('cyphrd.crypto.passphrases.dictionary');

goog.require('goog.array');
goog.require('goog.string');

// goog.require('cyphrd.crypto.utils');

/**
 * Checks to see if a passphrase is super simple.
 *  We check:
 *   - Min length at least 6
 *   - Passphrase is not entirely alpha, numeric, symbolic
 *
 * @param {string} phrase Passphrase to check.
 * @param {boolean=} opt_check_dictionary Check common dictionary (optional).
 *
 * @return {boolean} Whether this passphrase is super simple.
 */
cyphrd.crypto.passphrases.isSuperSimple = function(phrase, opt_check_dictionary) {
	var length = phrase.length;

	// Ensure passphrase is at least 7-characters
	// 6 characters is the most common password length, it's best to not allow it,
	// if you must, uncomment the dictionary below of 6-characters passphrases
	if (length < 7)
		return true;

	// Ensure passphrase is not entirely letters or numbers
	else if (goog.string.isAlpha(phrase) || goog.string.isNumeric(phrase))
		return true;

	// Ensure passphrase is not made of only special characters
	else if (/^[^a-zA-Z0-9]+$/.test(phrase))
		return true;

	// Ensure passphrase does not contain only one number (or symbol)
	// and it's at the beginning end of the passphrase.
	//
	// Why? The most common passphrases are:
	//  names, sport teams, generic objects, random words, repeated letters, followed by the number one.
	else if (goog.string.isAlpha(phrase.substr(1, length)) || goog.string.isAlpha(phrase.substr(0, length-1)))
	// else if (goog.string.isAlpha(phrase.replace(/^[0-9]|[0-9]$/g, ''))) // we do not use this because it not work as desired for passphrases beginning and ending with a number/symbol
		return true;

	else if (opt_check_dictionary && goog.array.contains(cyphrd.crypto.passphrases.dictionary.superSimple, phrase.toLowerCase()))
		return true;

	// Seems alright
	else
		return false;
};

/**
 * In addition to what isSuperSimple checks,
 *  We check:
 *   - Passphrase is not entirely alphanumeric (needs to contain a special character)
 *
 * @param {string} phrase Passphrase to check.
 * @param {boolean=} opt_check_dictionary Check common dictionary (optional).
 * @param {boolean=} opt_return_why Return why this password is considered simple (optional).
 *
 * @return {boolean|string} Whether this passphrase is simple.
 */
cyphrd.crypto.passphrases.isSimple = function(phrase, opt_check_dictionary, opt_return_why) {
	if (cyphrd.crypto.passphrases.isSuperSimple(phrase, false))
		return true;

	// Ensure passphrase is contains at least one special-character
	else if (goog.string.isAlphaNumeric(phrase))
		return opt_return_why ? 'isAlphaNumeric' : true;

	// Ensure passphrase is not a simple [numbers]words[numbers] setup
	// else if (goog.string.isAlpha(phrase.replace(/^[0-9]+|[0-9]+$/g, '')))
	// 	return opt_return_why ? '0W0' : true;

	else if (opt_check_dictionary && goog.array.contains(cyphrd.crypto.passphrases.dictionary.simple, phrase.toLowerCase()))
		return opt_return_why ? 'common' : true;

	return false;
};

/**
 * A dictionary of most-common passwords that still
 * would get through the isSuperSimple check.
 *
 */

// passwords that contain only letters and numbers
cyphrd.crypto.passphrases.dictionary.superSimple = [
	// 6-character passphrases
	// '12345a',
	// '123aaa',
	// '123abc',
	// '123asd',
	// '123qwe',
	// '1911a1',
	// '1a2b3c',
	// '1q2w3e',
	// '2hot4u',
	// '3000gt', // Older var from Mits, I used to own one
	// '3ki42x',
	// '3mpz4r',
	// '3x7pxr',
	// '4ng62t',
	// '4snz9g',
	// '50cent',
	// '56qhxs',
	// '57np39',
	// '6chid8',
	// '6uldv8',
	// '72d5tn',
	// '7kbe9d',
	// '7xm5rq',
	// '83y6pv',
	// '8dihc6',
	// '9skw5g',
	// 'a12345',
	// 'a1b2c3',
	// 'aaa111',
	// 'aaa340',
	// 'abc123',
	// 'abc123',
	// 'acls2h',
	// 'adam12',
	// 'adam25',
	// 'al9agd',
	// 'aol123',
	// 'area51',
	// 'asd123',
	// 'asdf12',
	// 'atc123',
	// 'bbb747',
	// 'bird33',
	// 'blue11',
	// 'blue12',
	// 'blue22',
	// 'blue23',
	// 'blue32',
	// 'blue42',
	// 'blue99',
	// 'bmw325',
	// 'bob123',
	// 'bp2002',
	// 'br0d3r',
	// 'c7lrwu',
	// 'cafc91',
	// 'came11',
	// 'cat123',
	// 'cbr600',
	// 'cbr900',
	// 'ch5nmk',
	// 'cn42qj',
	// 'colt45',
	// 'cq2kph',
	// 'd6o8pm',
	// 'd6wnro',
	// 'd9ebk7',
	// 'd9ungl',
	// 'de7mdf',
	// 'dga9la',
	// 'dhip6a',
	// 'dog123',
	// 'drag0n',
	// 'dte4uw',
	// 'e5pftu',
	// 'fdm7ed',
	// 'fqkw5m',
	// 'fuck69',
	// 'fx3tuo',
	// 'g3ujwg',
	// 'g9zns4',
	// 'gwju3g',
	// 'h2slca',
	// 'ha8fyp',
	// 'hpk2qc',
	// 'hr3ytm',
	// 'hun999',
	// 'i62gbq',
	// 'ib6ub9',
	// 'icu812',
	// 'intj3a',
	// 'joe123',
	// 'jys6wz',
	// 'k2trix',
	// 'kugm7b',
	// 'l2g7k3',
	// 'l8v53x',
	// 'lgnu9d',
	// 'love12',
	// 'love69',
	// 'm5wkqf',
	// 'max123',
	// 'mike23',
	// 'mike69',
	// 'mp8o6d',
	// 'ne1469',
	// 'nt5d27',
	// 'ou8122',
	// 'ou8123',
	// 'out3xf',
	// 'ov3ajy',
	// 'p3wqaw',
	// 'pic\'s',
	// 'pkxe62',
	// 'pn5jvw',
	// 'pwxd5x',
	// 'pyf8ah',
	// 'q1w2e3',
	// 'q9umoz',
	// 'qaz123',
	// 'qbg26i',
	// 'qn632o',
	// 'qqh92r',
	// 'qwe123',
	// 'r29hqq',
	// 'red123',
	// 'rjw7x4',
	// 'sam123',
	// 'sex123',
	// 'sex4me',
	// 'sexy69',
	// 'star12',
	// 'star69',
	// 'sxhq65',
	// 't26gn4',
	// 'test12',
	// 'tri5a3',
	// 'trs8f7',
	// 'ue8fpw',
	// 'usa123',
	// 'uwrl7c',
	// 'vh5150',
	// 'w00t88',
	// 'w4g8at',
	// 'waqw3p',
	// 'wu4etd',
	// 'wvj5np',
	// 'x24ik3',
	// 'x35v8l',
	// 'xirt2k',
	// 'xxx123',
	// 'xyz123',
	// 'zaq123',
	// 'zsmj2v',
	// 'zw6syj',
	// 'zxc123',

	// 7-letter passphrases
	'007bond', // James Bond, 007
	'123456a',
	'2fast4u',
	'3ep5w2u',
	'3ip76k2',
	'426hemi',
	'4getme2',
	'57chevy',
	'81fukkc',
	'a123456',
	'abc1234',
	'abcd123',
	'all4one',
	'asdf123',
	'blue123',
	'bond007', // James Bond, 007
	'bubba69',
	'bulls23',
	'catch22',
	'eatme69',
	'fuck123',
	'fucmy69',
	'gsxr750',
	'h179350',
	'hal9000',
	'heka6w2',
	'john123',
	'john316',
	'just4me',
	'keksa12',
	'letme1n',
	'love123',
	'lucky13',
	'magic32',
	'mario66',
	'met2002',
	'mike123',
	'ncc1701', // The ship number for the Starship Enterprise
	'nimda2k',
	'oicu812',
	'pass123',
	'pussy69',
	'qwert40',
	'rasta69',
	'route66',
	'sexy123',
	'sf49ers',
	'smk7366',
	'stone55',
	'temp123',
	'test123',
	'thx1138', // The name of George Lucas’s first movie, a 1971 remake of an earlier student project
	'tracy71',
	'turk182',
	'weed420',
	'wolf359',

	// 8-character passphrases
	'063dyjuy',
	'085tzzqi',
	'1234abcd',
	'1234qwer',
	'12locked',
	'12qwaszx',
	'151nxjmt',
	'154ugeiu',
	'1a2b3c4d',
	'1q2w3e4r',
	'1qaz2wsx',
	'1qazxsw2',
	'1x2zkg8w',
	'201jedlz',
	'20spanks',
	'23skidoo',
	'368ejhih',
	'380zliki',
	'383pdjvl',
	'474jdvff',
	'50spanks',
	'551scasi',
	'554uzpad',
	'55bgates',
	'5wr2i7h8',
	'69camaro',
	'766rglqy',
	'863abgsg',
	'8j4ye3uz',
	'911turbo',
	'a1234567',
	'a1b2c3d4',
	'abc12345',
	'abcd1234',
	'access14',
	'access14',
	'access99',
	'alpha123',
	'andyod22',
	'apollo13',
	'apple123',
	'asdf1234',
	'austin31',
	'b929ezzh',
	'blink182',
	'blue1234',
	'bubba123',
	'buddy123',
	'care1839',
	'cbr900rr',
	'cezer121',
	'chris123',
	'corvet07',
	'csfbr5yy',
	'dad2ownu',
	'dapzu455',
	'death666',
	'devil666',
	'dragon12',
	'dragon69',
	'f00tball',
	'ffvdj474',
	'flyers88',
	'fordf150',
	'front242',
	'gfxqx686',
	'gordon24',
	'green123',
	'gsxr1000',
	'happy123',
	'hawaii50',
	'hello123',
	'hihje863',
	'hs7mwxkk',
	'hzze929b',
	'iqzzt580',
	'isacs155',
	'james007',
	'jo9k2jw2',
	'jordan23',
	'just4fun',
	'kcj9wx5n',
	'luv2epus',
	'marino13',
	'mash4077',
	'master12',
	'mazda626',
	'money123',
	'monkey12',
	'mounta1n',
	'mwq6qlzo',
	'nancy123',
	'nascar24',
	'ncc1701a',
	'ncc1701d',
	'ncc1701e',
	'ncc74656',
	'nemrac58',
	'nwo4life',
	'ozlq6qwm',
	'pa55w0rd',
	'pa55word',
	'pass1234',
	'passw0rd',
	'ptfe3xxp',
	'pussy123',
	'pussy4me',
	'pxx3eftp',
	'q1w2e3r4',
	'qcmfd454',
	'qwer1234',
	'qwert123',
	'qwerty12',
	'r2d2c3po',
	'rasta220',
	'rt6ytere',
	'rush2012',
	'rush2112',
	'rush2112',
	'sanity72',
	'satan666',
	'save13tx',
	'shadow12',
	'soccer10',
	'soccer11',
	'soccer12',
	'ssptx452',
	'summer69',
	'summer99',
	'test1234',
	'tiger123',
	'tmjxn151',
	'turkey50',
	'wg8e3wjf',
	'winter99',
	'wp2003wp',
	'year2005',
	'yqlgr667',
	'yvtte545',
	'yy5rbfsc',
	'zaq12wsx',
	'zaq1xsw2',

	// 9-letter passphrases
	'fatluvr69',
	'fortune12',
	'gnasher23',
	'letmein22',
	'porn4life',
	'qwerty123',
	'slimed123',

	// above 9-letter passphrases
	'123qweasdzxc',
	'1q2w3e4r5t',
	'charlie123',
	'dookie4donuts',
	'password12',
	'password123',
	'password1234',
	'postov1000',
	'primetime21',
	'quant4307s'
];

// passwords that contain special characters
// even though these may appear "secure", they are common and are therefore
// likely to be bruteforced with a dictionary hack.
cyphrd.crypto.passphrases.dictionary.simple = [
	'0.0.0.000',
	'0.0.000',
	'changeme!',
	'close-up',
	'films+pic+galeries',
	'fuck_inside',
	'homepage-',
	'iloveyou!',
	'my_demarc' // my_DEMARC (default password for Demarc units)
];
