'use strict';

var _ = require('lodash');
var buffer = require('buffer');
var Bech32 = require('./bech32');

var Bech32Check = function Bech32Check(obj) {
  if (!(this instanceof Bech32Check))
    return new Bech32Check(obj);
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

Bech32Check.prototype.set = function(obj) {
  this.buf = obj.buf || this.buf || undefined;
  return this;
};

Bech32Check.validChecksum = function validChecksum(data, checksum) {
  if (_.isString(data)) {
    data = new buffer.Buffer(Base58.decode(data));
  }
  if (_.isString(checksum)) {
    checksum = new buffer.Buffer(Base58.decode(checksum));
  }
  if (!checksum) {
    checksum = data.slice(-4);
    data = data.slice(0, -4);
  }
  return Bech32Check.checksum(data).toString('hex') === checksum.toString('hex');
};

Bech32Check.decode = function(s) {
  if (typeof s !== 'string')
    throw new Error('Input must be a string');
  return Bech32.decode(s);
};

Bech32Check.checksum = function(buffer) {
  return sha256sha256(buffer).slice(0, 4);
};

Bech32Check.encode = function(buf, prefix) {
  if (!Buffer.isBuffer(buf))
    throw new Error('Input must be a buffer');
  return Bech32.encode(buf, null, prefix);
};

Bech32Check.prototype.fromBuffer = function(buf) {
  this.buf = buf;
  return this;
};

Bech32Check.prototype.fromString = function(str) {
  var buf = Bech32Check.decode(str);
  this.buf = buf;
  return this;
};

Bech32Check.prototype.toBuffer = function() {
  return this.buf;
};

Bech32Check.prototype.toString = function() {
  return Bech32Check.encode(this.buf);
};

module.exports = Bech32Check;
