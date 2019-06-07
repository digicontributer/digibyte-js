'use strict';

var _ = require('lodash');
var $ = require('../util/preconditions');
var Base58Check = require('../encoding/base58check');
var Hash = require('../crypto/hash');
var Address = require('../address');
var JSUtil = require('../util/js');

var POSTFIXBYTELENGTH = 2;
var UNLOCKEPADDING = {
  aggregatable: 0x2e37,
  hybrid: 0x2e6b,
  dispersed: 0x2e4e
}
var LOCKEPADDING = {
  aggregatable: 0x20ce,
  hybrid: 0x2102,
  dispersed: 0x20e4
}

var OP_CODES = {
  'issuance': {
    'start': 0x00,
    'end': 0x0f,
    'encoder': require('digiasset-issuance-encoder')
  },
  'transfer': {
    'start': 0x10,
    'end': 0x1f,
    'encoder': require('digiasset-transfer-encoder')
  },
  'burn': {
    'start': 0x20,
    'end': 0x2f,
    'encoder': require('digiasset-transfer-encoder')
  }
}

var encodingLookup = {}

for (var transactionType in OP_CODES) {
  for (var j = OP_CODES[transactionType].start; j <= OP_CODES[transactionType].end; j++) {
    encodingLookup[j] = {}
    encodingLookup[j].encode = OP_CODES[transactionType].encoder.encode
    encodingLookup[j].decode = OP_CODES[transactionType].encoder.decode
    encodingLookup[j].type = transactionType
  }
}

var paymentsInputToSkip = function (payments) {
  var result = JSON.parse(JSON.stringify(payments))
  result.sort(function (a, b) {
    return a.input - b.input
  })
  for (var i = 0; i < result.length; i++) {
    var skip = false
    if (result[i + 1] && result[i + 1].input > result[i].input) {
      skip = true
    }
    delete result[i].input
    result[i].skip = skip
  }
  return result
}

var paymentsSkipToInput = function (payments) {
  var paymentsDecoded = []
  var input = 0
  for (var i = 0; i < payments.length; i++) {
    var paymentDecoded = payments[i].burn ? {burn: true} : {range: payments[i].range, output: payments[i].output}
    paymentDecoded.input = input
    paymentDecoded.percent = payments[i].percent
    paymentDecoded.amount = payments[i].amount
    paymentsDecoded.push(paymentDecoded)
    if (payments[i].skip) input = input + 1
  }
  return paymentsDecoded
}

/**
 * Represents a digiasset,
 *
 * @constructor
 * @param {object} data
 * @param {string} data.type digiasset encoding type
 * @param {string} data.noRules 
 * @param {array} data.payments any payments including in the transaction
 * @param {string} data.protocol the asset protocol
 * @param {string} data.version digiasset transaction version
 * @param {string} data.lockStatus  is the data locked
 * @param {string} data.aggregationPolicy asset aggregation policy
 * @param {number} data.divisibility asset divisibility
 * @param {array} data.multiSig any associated multisig addresses
 * @param {number} data.amount the amount being transfered
 * @param {string} data.sha2 the sha2 hash of the torrent if included
 * @param {string} data.torrentHash trrent hash
 */
function DigiAsset(data) {
  /* jshint maxcomplexity: 20 */
  /* jshint maxstatements: 20 */
  if ((this instanceof DigiAsset) && data.type) {
    return data;
  }
  if (!(this instanceof DigiAsset)) {
    return new DigiAsset(data);
  }
  $.checkArgument(_.isObject(data), 'Must provide an object from where to extract data');
  this.assetId = '';
  this.aggregationPolicy = 'aggregatable';
  this.divisibility = 0;
  this.lockStatus = true;
  this.fromBuffer(data); 
}

DigiAsset.prototype.fromBuffer = function(data) {
  var decoder = encodingLookup[data[3]];
  var rawData = decoder.decode(data);
  this.protocol = rawData.protocol;
  this.version = rawData.version;
  this.multiSig = rawData.multiSig || [];
  this.payments = paymentsSkipToInput(rawData.payments);
  this.type = decoder.type;
  if (this.type === 'issuance') {
    this.lockStatus = rawData.lockStatus
    this.aggregationPolicy = rawData.aggregationPolicy
    this.divisibility = rawData.divisibility
    this.amount = rawData.amount
  }  
  return this;
};

DigiAsset.prototype.padLeadingZeros  = function(hex, byteSize) {
  if (!byteSize) {
    byteSize = Math.ceil(hex.length / 2);
  }
  return (hex.length === byteSize * 2) ? hex : this.padLeadingZeros('0' + hex, byteSize);
};

DigiAsset.prototype.getAssetId = function(firstInput) {
  var script = firstInput.script;
  var firstInputObj = firstInput.toObject();
  var padding;
  if (this.lockStatus) {
    padding = LOCKEPADDING[this.aggregationPolicy];
    return this.createIdFromTxidIndex(firstInputObj, padding);
  }

  padding = UNLOCKEPADDING[this.aggregationPolicy];
  if (firstInputObj.previousOutput && firstInputObj.previousOutput.hex) {
    return createIdFromPreviousOutputScriptPubKey(firstInputObj.previousOutput.hex, padding, divisibility);
  }
  return this.createIdFromPubKeyHashInput(script, padding);
};

DigiAsset.prototype.createIdFromTxidIndex = function(firstInput, padding) {
  var str = firstInput.prevTxId + ':' + firstInput.outputIndex;
  return this.hashAndBase58CheckEncode(Buffer.from(str), padding);
};

DigiAsset.prototype.createIdFromPubKeyHashInput = function(script, padding) {
  var Script = require('../script');
  var pubKeyHash = new Address(Hash.sha256ripemd160(script.chunks[1].buf));
  var pubKeyHashOutput = Script.buildPublicKeyHashOut(pubKeyHash).toBuffer();
  return this.hashAndBase58CheckEncode(pubKeyHashOutput, padding)
};

DigiAsset.prototype.hashAndBase58CheckEncode  = function(payloadToHash, padding) {
  var hash256 = Hash.sha256(payloadToHash);
  var hash160 = Hash.ripemd160(hash256);
  padding = new Buffer(this.padLeadingZeros(padding.toString(16)), 'hex');
  this.divisibility = new Buffer(this.padLeadingZeros(this.divisibility.toString(16), POSTFIXBYTELENGTH), 'hex');
  var concatenation = Buffer.concat([padding, hash160, this.divisibility]);
  this.assetId = Base58Check.encode(concatenation);
  return this;
};


/**
 * Provide an informative output when displaying this object in the console
 * @returns string
 */
DigiAsset.prototype.inspect = function() {
  if(this.type === 'issuance') {
    return '<DigiAsset: assetId: ' + this.assetId + ', type: ' + this.type + ', amount: ' + this.amount + 
    ', protocol: ' + this.protocol + ', version: ' + this.version +
    ', multisig: ' + this.multiSig.length + ', payments: ' + this.payments.length + '>';    
  }
  return '<DigiAsset: type: ' + this.type + ', protocol: ' + this.protocol + ', version: ' + this.version +
         ', multisig: ' + this.multiSig.length + ', payments: ' + this.payments.length + '>';
};

/**
 * String representation: just "txid:index"
 * @returns string
 */
DigiAsset.prototype.toString = function() {
  return this.txId + ':' + this.outputIndex;
};

/**
 * Deserialize an UnspentOutput from an object
 * @param {object|string} data
 * @return UnspentOutput
 */
DigiAsset.fromObject = function(data) {
  return new DigiAsset(data);
};

/**
 * Returns a plain object (no prototype or methods) with the associated info for this output
 * @return {object}
 */
DigiAsset.prototype.toObject = DigiAsset.prototype.toJSON = function toObject() {
  return {
    assetId: this.assetId,
    type: this.type,
    amount: this.amount,
    protocol: this.protocol,
    version: this.version,
    type: this.type,
    multiSig: this.multiSig,
    payments: this.script.payments()
  };
};

module.exports = DigiAsset;