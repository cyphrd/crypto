var dict = require('./passphrases.dict.json');

var isAlpha = /^[a-zA-Z]+$/;
var isNumeric = /^[0-9]+$/;
var isAlphaNumeric = /^[^a-zA-Z0-9]+$/;

/**
 * Checks to see if a passphrase is super simple.
 *  We check:
 *   - Min length at least 7
 *   - Passphrase is not entirely alpha, numeric (like: deadbeef or 1234567890)
 *   - Does not start or end with a single number or symbol and the rest is alpha chars (like: pass1)
 *
 * @param {string} phrase Passphrase to check.
 * @param {boolean=} opt_check_dictionary Check common dictionary (optional).
 *
 * @return {boolean} Whether this passphrase is super simple.
 */
module.exports.isSuperSimple = function (phrase, opt_check_dictionary) {
	var length = phrase.length;

	// Ensure passphrase is at least 7-chars
	// 6 chars is the most common pass length, best to have 7 as the min.
	if (length < 7)
		return true;

	// Ensure passphrase is not entirely letters or numbers
	else if (isAlpha.test(phrase) || isNumeric.test(phrase))
		return true;

	// Ensure passphrase is not made of only special characters
	else if (isAlphaNumeric.test(phrase))
		return true;

	// Ensure passphrase does not contain only one number (or symbol) that is at the beginning end of the passphrase.
	//
	// Why? The most common passphrases are:   
	//  names, sport teams, generic objects, dictionary words, repeated letters, followed by the number one.
	else if (isAlpha.test(phrase.substr(1, length)) || isAlpha.test(phrase.substr(0, length-1)))
		return true;

	else if (opt_check_dictionary && goog.array.contains(dict, phrase.toLowerCase()))
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
module.exports.isSimple = function (phrase, opt_check_dictionary, opt_return_why) {
	// passwords that contain special characters
	// even though these may appear "secure", they are common and are therefore
	// likely to be bruteforced with a dictionary hack.
	var dictionary = [
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

	if (module.exports.isSuperSimple(phrase, false))
		return true;

	// Ensure passphrase is contains at least one special-character
	else if (isAlphaNumeric.test(phrase))
		return opt_return_why ? 'isAlphaNumeric' : true;

	// Ensure passphrase is not a simple [numbers]words[numbers] setup
	// else if (goog.string.isAlpha(phrase.replace(/^[0-9]+|[0-9]+$/g, '')))
	// 	return opt_return_why ? '0W0' : true;

	else if (opt_check_dictionary && goog.array.contains(dictionary, phrase.toLowerCase()))
		return opt_return_why ? 'common' : true;

	return false;
};
