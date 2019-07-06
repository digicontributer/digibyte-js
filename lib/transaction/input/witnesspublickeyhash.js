'use strict';

var inherits = require('inherits');

var $ = require('../../util/preconditions');
var BufferWriter = require('../../encoding/bufferwriter');
var BufferUtil = require('../../util/buffer');
var Opcode = require('../../opcode');

var Hash = require('../../crypto/hash');
var Input = require('./input');
var Output = require('../output');
var Sighash = require('../sighashwitness');
var Script = require('../../script');
var Signature = require('../../crypto/signature');
var TransactionSignature = require('../signature');

/**
 * Represents a special kind of input of PayToPublicKeyHash kind.
 * @constructor
 */
function WitnessPublicKeyHashInput() {
  Input.apply(this, arguments);
}
inherits(WitnessPublicKeyHashInput, Input);

/* jshint maxparams: 5 */
/**
 * @param {Transaction} transaction - the transaction to be signed
 * @param {PrivateKey} privateKey - the private key with which to sign the transaction
 * @param {number} index - the index of the input in the transaction input vector
 * @param {number=} sigtype - the type of signature, defaults to Signature.SIGHASH_ALL
 * @param {Buffer=} hashData - the precalculated hash of the public key associated with the privateKey provided
 * @return {Array} of objects that can be
 */
WitnessPublicKeyHashInput.prototype.getSignatures = function(transaction, privateKey, index, sigtype, hashData) {
  $.checkState(this.output instanceof Output);
  hashData = hashData || Hash.sha256ripemd160(privateKey.publicKey.toBuffer());
  sigtype = sigtype || Signature.SIGHASH_ALL;
  var satoshisBuffer = this.getSatoshisBuffer();
  if (BufferUtil.equals(hashData, this.output.script.getWitnessPublicKeyHash())) {
    return [new TransactionSignature({
      publicKey: privateKey.publicKey,
      prevTxId: this.prevTxId,
      outputIndex: this.outputIndex,
      inputIndex: index,
      signature: Sighash.sign(transaction, privateKey, sigtype, index, this.getPaymentScriptBuffer(), satoshisBuffer),
      sigtype: sigtype
    })];
  }
  return [];
};
/* jshint maxparams: 3 */

/**
 * Add the provided signature
 *
 * @param {Object} signature
 * @param {PublicKey} signature.publicKey
 * @param {Signature} signature.signature
 * @param {number=} signature.sigtype
 * @return {PublicKeyHashInput} this, for chaining
 */
WitnessPublicKeyHashInput.prototype.addSignature = function(transaction, signature) {
  $.checkState(this.isValidSignature(transaction, signature), 'Signature is invalid');
  var stack = [];
  stack.push(BufferUtil.concat([
    signature.signature.toDER(),
    BufferUtil.integerAsSingleByteBuffer(signature.sigtype)
  ]));
  stack.push(signature.publicKey.toBuffer());
  this.setWitnesses(stack); 
  return this;
};

/**
 * Clear the input's signature
 * @return {PublicKeyHashInput} this, for chaining
 */
WitnessPublicKeyHashInput.prototype.clearSignatures = function() {
  this.setScript(Script.empty());
  return this;
};

WitnessPublicKeyHashInput.prototype.isValidSignature = function(transaction, signature) {
  signature.signature.nhashtype = signature.sigtype;
  var scriptCode = this.getScriptCode(signature.publicKey);
  var satoshisBuffer = this.getSatoshisBuffer();
  return Sighash.verify(
    transaction,
    signature.signature,
    signature.publicKey,
    signature.inputIndex,
    scriptCode,
    satoshisBuffer
  );
};

WitnessPublicKeyHashInput.prototype.getPaymentScript = function() {
  var witnesspubkeyhash = this.output.script.getWitnessPublicKeyHash();
  return new Script()
    .add(Opcode.OP_DUP)
    .add(Opcode.OP_HASH160)
    .add(witnesspubkeyhash)
    .add(Opcode.OP_EQUALVERIFY)
    .add(Opcode.OP_CHECKSIG);
};

WitnessPublicKeyHashInput.prototype.getPaymentScriptBuffer = function() {
  var s = this.getPaymentScript();
  return BufferUtil.concat([
    Buffer.from([s.toBuffer().length]),
    s.toBuffer()
  ]);
};


WitnessPublicKeyHashInput.prototype.getScriptCode = function() {
  var writer = new BufferWriter();
  var s = this.getPaymentScript();
  if (!s.hasCodeseparators()) {
    var redeemScriptBuffer = s.toBuffer();
    writer.writeVarintNum(redeemScriptBuffer.length);
    writer.write(redeemScriptBuffer);
  } else {
    throw new Error('@TODO');
  }
  return writer.toBuffer();
};

WitnessPublicKeyHashInput.prototype.isFullySigned = function() {
  return true;
};


module.exports = WitnessPublicKeyHashInput;
