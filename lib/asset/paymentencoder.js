'use strict';

var $ = require('../util/preconditions');
var assetUtils = require('../util/assets');
var sffc = require('sffc-encoder');

var flagMask = 0xe0;
var skipFlag = 0x80;
var rangeFlag = 0x40;
var percentFlag = 0x20;

function PaymentEncoder(params) {
  if (!(this instanceof PaymentEncoder)) {
    return new PaymentEncoder(params);
  }
  if(params) {
    this.skip = params.skip || false;
    this.range = params.range || false;
    this.percent = params.percent || false;
    this.output = params.output;
    this.amount = params.amount;
  }
}

PaymentEncoder.prototype.encode = function() {
  $.checkState(this.amount, 'Needs an amount value');
  var outputBinaryLength = this.output.toString(2).length;
  if (this.output < 0) throw new Error('Output Can\'t be negative');
  if ((!this.range && outputBinaryLength > 5) || (this.range && outputBinaryLength > 13)) {
    throw new Error('Output value is out of bounds');
  }
  var outputString = assetUtils.padLeadingZeros(this.output.toString(16), +this.range + 1);
  var buf = new Buffer(outputString, 'hex');
  if (this.skip) buf[0] = buf[0] | skipFlag;
  if (this.range) buf[0] = buf[0] | rangeFlag;
  if (this.percent) buf[0] = buf[0] | percentFlag;

  return Buffer.concat([buf, sffc.encode(this.amount)]);
}

PaymentEncoder.prototype.decode = function(consume) {
  var flagsBuffer = consume(1)[0];
  $.checkState(flagsBuffer, 'No flags found');
  this.output = new Buffer([flagsBuffer & (~flagMask)]);
  this.flags = flagsBuffer & flagMask;
  this.skip = !!(this.flags & skipFlag);
  this.range = !!(this.flags & rangeFlag);
  this.percent = !!(this.flags & percentFlag);
  if (this.range) {
    this.output = Buffer.concat([this.output, consume(1)]);
  }
  this.amount = sffc.decode(consume);
  return new PaymentEncoder({ skip: this.skip, range: this.range, percent: this.percent, output: parseInt(this.output.toString('hex'), 16), amount: this.amount });
}

PaymentEncoder.prototype.encodeBulk = function(paymentsArray) {
  var payments = new Buffer(0);
  var amountOfPayments = paymentsArray.length;
  for (var i = 0; i < amountOfPayments; i++) {
    var payment = new PaymentEncoder(paymentsArray[i]);
    var paymentCode = payment.encode();
    payments = Buffer.concat([payments, paymentCode]);
  }
  return payments;
}

PaymentEncoder.prototype.decodeBulk = function(consume, paymentsArray) {
  paymentsArray = paymentsArray || [];
  while (true) {
    try {
      var decoded = new PaymentEncoder();
      paymentsArray.push(decoded.decode(consume));
      this.decodeBulk(consume, paymentsArray);
    } catch (e) {
      return paymentsArray;
    }
  };
}

module.exports = PaymentEncoder;