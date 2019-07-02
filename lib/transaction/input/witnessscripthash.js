'use strict';

/* jshint maxparams:5 */

var _ = require('lodash');
var inherits = require('inherits');
var Input = require('./input');
var Output = require('../output');
var $ = require('../../util/preconditions');

var Script = require('../../script');
var Signature = require('../../crypto/signature');
var Sighash = require('../sighash');
var SighashWitness = require('../sighashwitness');
var BufferWriter = require('../../encoding/bufferwriter');
var BufferUtil = require('../../util/buffer');
var TransactionSignature = require('../signature');

/**
 * @constructor
 */
function WitnessScriptHash(input, pubkeys, threshold, signatures) {
  /* jshint maxstatements:20 */
  Input.apply(this, arguments);
  var self = this;
  pubkeys = pubkeys || input.publicKeys;
  threshold = threshold || input.threshold;
  signatures = signatures || input.signatures;
  this.publicKeys = _.sortBy(pubkeys, function(publicKey) { return publicKey.toString('hex'); });
  this.redeemScript = Script.buildMultisigOut(this.publicKeys, threshold);
  var nested = Script.buildWitnessMultisigOutFromScript(this.redeemScript);
  $.checkState(nested.equals(this.output.script),
               'Provided public keys don\'t hash to the provided output (nested witness)');

  this.publicKeyIndex = {};
  _.each(this.publicKeys, function(publicKey, index) {
    self.publicKeyIndex[publicKey.toString()] = index;
  });
  this.threshold = threshold;
  // Empty array of signatures
  this.signatures = signatures ? this._deserializeSignatures(signatures) : new Array(this.publicKeys.length);
}
inherits(WitnessScriptHash, Input);

WitnessScriptHash.prototype.toObject = function() {
  var obj = Input.prototype.toObject.apply(this, arguments);
  obj.threshold = this.threshold;
  obj.publicKeys = _.map(this.publicKeys, function(publicKey) { return publicKey.toString(); });
  obj.signatures = this._serializeSignatures();
  return obj;
};

WitnessScriptHash.prototype._deserializeSignatures = function(signatures) {
  return _.map(signatures, function(signature) {
    if (!signature) {
      return undefined;
    }
    return new TransactionSignature(signature);
  });
};

WitnessScriptHash.prototype._serializeSignatures = function() {
  return _.map(this.signatures, function(signature) {
    if (!signature) {
      return undefined;
    }
    return signature.toObject();
  });
};

WitnessScriptHash.prototype.getScriptCode = function() {
  var writer = new BufferWriter();
  if (!this.redeemScript.hasCodeseparators()) {
    var redeemScriptBuffer = this.redeemScript.toBuffer();
    writer.writeVarintNum(redeemScriptBuffer.length);
    writer.write(redeemScriptBuffer);
  } else {
    throw new Error('@TODO');
  }
  return writer.toBuffer();
};

WitnessScriptHash.prototype.getSighash = function(transaction, privateKey, index, sigtype) {
  var self = this;
  var hash;
  var scriptCode = self.getScriptCode();
  var satoshisBuffer = self.getSatoshisBuffer();
  hash = SighashWitness.sighash(transaction, sigtype, index, scriptCode, satoshisBuffer);
  return hash;
};

WitnessScriptHash.prototype.getSignatures = function(transaction, privateKey, index, sigtype) {
  $.checkState(this.output instanceof Output);
  sigtype = sigtype || Signature.SIGHASH_ALL;

  var self = this;
  var results = [];
  _.each(this.publicKeys, function(publicKey) {
    if (publicKey.toString() === privateKey.publicKey.toString()) {
      var signature;
      var scriptCode = self.getScriptCode();
      var satoshisBuffer = self.getSatoshisBuffer();
      //transaction.version = 2;
      signature = SighashWitness.sign(transaction, privateKey, sigtype, index, scriptCode, satoshisBuffer);
      results.push(new TransactionSignature({
        publicKey: privateKey.publicKey,
        prevTxId: self.prevTxId,
        outputIndex: self.outputIndex,
        inputIndex: index,
        signature: signature,
        sigtype: sigtype
      }));
    }
  });
  return results;
};

WitnessScriptHash.prototype.addSignature = function(transaction, signature) {
  $.checkState(!this.isFullySigned(), 'All needed signatures have already been added');
  $.checkArgument(!_.isUndefined(this.publicKeyIndex[signature.publicKey.toString()]),
                  'Signature has no matching public key');
  $.checkState(this.isValidSignature(transaction, signature));
  this.signatures[this.publicKeyIndex[signature.publicKey.toString()]] = signature;
  this._updateScript();
  return this;
};

WitnessScriptHash.prototype._updateScript = function() {
  var stack = [
    Buffer.alloc(0)
  ];
  var signatures = this._createSignatures();
  for (var i = 0; i < signatures.length; i++) {
    stack.push(signatures[i]);
  }
  stack.push(this.redeemScript.toBuffer());
  this.setWitnesses(stack);
  return this;
};

WitnessScriptHash.prototype._createSignatures = function() {
  return _.map(
    _.filter(this.signatures, function(signature) { return !_.isUndefined(signature); }),
    function(signature) {
      return BufferUtil.concat([
        signature.signature.toDER(),
        BufferUtil.integerAsSingleByteBuffer(signature.sigtype)
      ]);
    }
  );
};

WitnessScriptHash.prototype.clearSignatures = function() {
  this.signatures = new Array(this.publicKeys.length);
  this._updateScript();
};

WitnessScriptHash.prototype.isFullySigned = function() {
  return this.countSignatures() === this.threshold;
};

WitnessScriptHash.prototype.countMissingSignatures = function() {
  return this.threshold - this.countSignatures();
};

WitnessScriptHash.prototype.countSignatures = function() {
  return _.reduce(this.signatures, function(sum, signature) {
    return sum + (!!signature);
  }, 0);
};

WitnessScriptHash.prototype.publicKeysWithoutSignature = function() {
  var self = this;
  return _.filter(this.publicKeys, function(publicKey) {
    return !(self.signatures[self.publicKeyIndex[publicKey.toString()]]);
  });
};

WitnessScriptHash.prototype.isValidSignature = function(transaction, signature) {
  signature.signature.nhashtype = signature.sigtype;
  var scriptCode = this.getScriptCode();
  var satoshisBuffer = this.getSatoshisBuffer();
  return SighashWitness.verify(
    transaction,
    signature.signature,
    signature.publicKey,
    signature.inputIndex,
    scriptCode,
    satoshisBuffer
  );
};

WitnessScriptHash.OPCODES_SIZE = 7; // serialized size (<=3) + 0 .. N .. M OP_CHECKMULTISIG
WitnessScriptHash.SIGNATURE_SIZE = 74; // size (1) + DER (<=72) + sighash (1)
WitnessScriptHash.PUBKEY_SIZE = 34; // size (1) + DER (<=33)

WitnessScriptHash.prototype._estimateSize = function() {
  return WitnessScriptHash.OPCODES_SIZE +
    this.threshold * WitnessScriptHash.SIGNATURE_SIZE +
    this.publicKeys.length * WitnessScriptHash.PUBKEY_SIZE;
};

module.exports = WitnessScriptHash;