'use strict';

var $ = require('../util/preconditions');
var assetUtils = require('../util/assets');
var PaymentEncoder = require('./paymentencoder');

var BURN_OUTPUT = 0x1f

function BurnPaymentEncoder(params) {
  if (!(this instanceof BurnPaymentEncoder)) {
    return new BurnPaymentEncoder(params);
  }
  this.amount = params.amount;
  this.output = params.output;
  this.range = params.range;
  this.burn = params.burn;
}

BurnPaymentEncoder.prototype.encode = function() {
  if (typeof this.output === 'undefined' && !this.burn) {
    throw new Error('Needs output value or burn flag');
  }
  if (typeof this.output !== 'undefined' && this.burn) {
    throw new Error('Received both burn and output');
  }
  if (typeof this.range !== 'undefined' && this.burn) {
    throw new Error('Received both burn and range');
  }
  if (!this.range && this.output === BURN_OUTPUT) {
    throw new Error('Received range and output values reserved to represent burn (to indicate burn use burn flag)');
  }

  var paymentObject = this;
  if (this.burn) {
    paymentObject = new PaymentEncoder(paymentObject);
    paymentObject.output = BURN_OUTPUT;
    paymentObject.range = false;
    paymentObject.amount = this.amount;
    delete paymentObject.burn;
  }

  return new PaymentEncoder(paymentObject).encode(paymentObject);
}

BurnPaymentEncoder.prototype.decode = function(consume) {
  var ans = new PaymentEncoder().decode(consume);
  var burn = !ans.range && (ans.output === BURN_OUTPUT);
  if (burn) {
    ans.burn = true
    delete ans.output;
    delete ans.range;
  }
  return new BurnPaymentEncoder(ans);
}

BurnPaymentEncoder.prototype.encodeBulk = function(paymentsArray, isBurn) {
  var payments = new Buffer(0);
  var amountOfPayments = paymentsArray.length;
  for (var i = 0; i < amountOfPayments; i++) {
    var payment = new BurnPaymentEncoder(paymentsArray[i]);
    var paymentCode = payment.encode();
    payments = Buffer.concat([payments, paymentCode]);
  }
  return payments;
}

BurnPaymentEncoder.prototype.decodeBulk = function(consume, paymentsArray) {
  paymentsArray = paymentsArray || [];
  while (true) {
    try {
      paymentsArray.push(new BurnPaymentEncoder().decode(consume));
      this.decodeBulk(consume, paymentsArray);
    } catch (e) {
      return paymentsArray;
    }
  }
}


module.exports = BurnPaymentEncoder;