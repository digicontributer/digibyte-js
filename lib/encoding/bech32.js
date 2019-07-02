'use strict';

var _ = require('lodash');
var bs58 = require('bs58');
var buffer = require('buffer');

var ALPHABET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
var ALPHABET_MAP = {};

for (var z = 0; z < ALPHABET.length; z++) {
  var x = ALPHABET.charAt(z)

  if (ALPHABET_MAP[x] !== undefined) throw new TypeError(x + ' is ambiguous')
  ALPHABET_MAP[x] = z
}

var Bech32 = function Bech32(obj) {
  /* jshint maxcomplexity: 8 */
  if (!(this instanceof Bech32)) {
    return new Bech32(obj);
  }
  if (Buffer.isBuffer(obj)) {
    var buf = obj;
    this.fromBuffer(buf);
  } else if (typeof obj === 'string') {
    var str = obj;
    this.fromString(str);
  } else if (obj) {
    this.set(obj);
  }
};

Bech32.prototype.validCharacters = function validCharacters(chars) {
  if (buffer.Buffer.isBuffer(chars)) {
    chars = chars.toString();
  }
  return _.all(_.map(chars, function(char) { return _.contains(ALPHABET, char); }));
};

Bech32.polymodStep = function polymodStep (pre) {
  var b = pre >> 25
  return ((pre & 0x1FFFFFF) << 5) ^
    (-((b >> 0) & 1) & 0x3b6a57b2) ^
    (-((b >> 1) & 1) & 0x26508e6d) ^
    (-((b >> 2) & 1) & 0x1ea119fa) ^
    (-((b >> 3) & 1) & 0x3d4233dd) ^
    (-((b >> 4) & 1) & 0x2a1462b3)
}

Bech32.prefixChk = function prefixChk (prefix) {
  var chk = 1;
  for (var i = 0; i < prefix.length; ++i) {
    var c = prefix.charCodeAt(i)
    if (c < 33 || c > 126) throw new Error('Invalid prefix (' + prefix + ')')

    chk = Bech32.polymodStep(chk) ^ (c >> 5)
  }
  chk = Bech32.polymodStep(chk)
  for (i = 0; i < prefix.length; ++i) {
    var v = prefix.charCodeAt(i)
    chk = Bech32.polymodStep(chk) ^ (v & 0x1f)
  }
  return chk
}

Bech32.prototype.set = function(obj) {
  this.buf = obj.buf || this.buf || undefined;
  return this;
};

Bech32.convert = function convert (data, inBits, outBits, pad) {
  var value = 0
  var bits = 0
  var maxV = (1 << outBits) - 1

  var result = []
  for (var i = 0; i < data.length; ++i) {
    value = (value << inBits) | data[i]
    bits += inBits

    while (bits >= outBits) {
      bits -= outBits
      result.push((value >> bits) & maxV)
    }
  }

  if (pad) {
    if (bits > 0) {
      result.push((value << (outBits - bits)) & maxV)
    }
  } else {
    if (bits >= inBits) throw new Error('Excess padding')
    if ((value << (outBits - bits)) & maxV) throw new Error('Non-zero padding')
  }

  return result
};

Bech32.encode = function(buf, LIMIT, prefix) {
  if (!buffer.Buffer.isBuffer(buf)) {
    throw new Error('Input should be a buffer');
  }

  LIMIT = LIMIT || 90;
  if (!prefix) {
    prefix = 'dgb';
  }
  if ((prefix.length + 7 + buf.length) > LIMIT)
    throw new Error('Exceeds length limit');

  prefix = prefix.toLowerCase();

  // determine chk mod
  var chk = Bech32.prefixChk(prefix);
  var result = prefix + '1';
  for (var i = 0; i < buf.length; ++i) {
    var x = buf[i];
    if ((x >> 5) !== 0)
      throw new Error('Non 5-bit word');

    chk = Bech32.polymodStep(chk) ^ x;
    result += ALPHABET.charAt(x);
  }

  for (i = 0; i < 6; ++i) {
    chk = Bech32.polymodStep(chk);
  }
  chk ^= 1;

  for (i = 0; i < 6; ++i) {
    var v = (chk >> ((5 - i) * 5)) & 0x1f;
    result += ALPHABET.charAt(v);
  }
  return result;
};

Bech32.decode = function(str, LIMIT) {
  if (typeof str !== 'string') {
    throw new Error('Input should be a string');
  }

  LIMIT = LIMIT || 90
  if (str.length < 8)
    throw new Error(str + ' too short');
  if (str.length > LIMIT)
    throw new Error('Exceeds length limit');

  // don't allow mixed case
  var lowered = str.toLowerCase();
  var uppered = str.toUpperCase();
  if (str !== lowered && str !== uppered)
    throw new Error('Mixed-case string ' + str);
  str = lowered;

  var split = str.lastIndexOf('1');
  if (split === -1)
    throw new Error('No separator character for ' + str);
  if (split === 0)
    throw new Error('Missing prefix for ' + str);

  var prefix = str.slice(0, split);
  var wordChars = str.slice(split + 1);
  if (wordChars.length < 6)
    throw new Error('Data too short');

  var chk = Bech32.prefixChk(prefix);
  
  var words = [];
  for (var i = 0; i < wordChars.length; ++i) {
    var c = wordChars.charAt(i);
    var v = ALPHABET_MAP[c];
    if (v === undefined)
      throw new Error('Unknown character ' + c)
    chk = Bech32.polymodStep(chk) ^ v;

    // not in the checksum?
    if (i + 6 >= wordChars.length) continue
    words.push(v);
  }

  if (chk !== 1)
    throw new Error("Checksum mismatch");
  return words;
};

Bech32.toWords = function(bytes) {
  return Bech32.convert(bytes, 8, 5, true);
};

Bech32.fromWords = function(words) {
  return Bech32.convert(words, 5, 8, false);
};

Bech32.prototype.fromBuffer = function(buf) {
  this.buf = buf;
  return this;
};

Bech32.prototype.fromString = function(str) {
  var buf = Bech32.decode(str);
  this.buf = buf;
  return this;
};

Bech32.prototype.toBuffer = function() {
  return this.buf;
};

Bech32.prototype.toString = function() {
  return Bech32.encode(this.buf);
};

module.exports = Bech32;
