'use strict';

var _ = require('lodash');
var $ = require('../util/preconditions');
var JSUtil = require('../util/js');

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
  if (!(this instanceof DigiAsset)) {
    return new DigiAsset(data);
  }
  $.checkArgument(_.isObject(data), 'Must provide an object from where to extract data');
  console.log(data[3]);
  var decoder = encodingLookup[data[3]]
  JSUtil.defineImmutable(this, {
    address: address,
    txId: txId,
    outputIndex: outputIndex,
    script: script,
    satoshis: amount
  });
}

/**
 * Provide an informative output when displaying this object in the console
 * @returns string
 */
DigiAsset.prototype.inspect = function() {
  return '<DigiAsset: ' + this.txId + ':' + this.outputIndex +
         ', satoshis: ' + this.satoshis + ', address: ' + this.address + '>';
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
    address: this.address ? this.address.toString() : undefined,
    txid: this.txId,
    vout: this.outputIndex,
    scriptPubKey: this.script.toBuffer().toString('hex'),
    amount: Unit.fromSatoshis(this.satoshis).toDGB()
  };
};

module.exports = DigiAsset;