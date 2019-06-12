'use strict';

var $ = require('../util/preconditions');
var assetUtils = require('../util/assets');
var IssueFlagsEncoder = require('./issueflagsencoder.js');
var PaymentEncoder = require('./paymentencoder');
var sffc = require('sffc-encoder');

var OP_CODES = [
  new Buffer([0x00]), // wild-card to be defined
  new Buffer([0x01]), // All Hashes in OP_RETURN - Pay-to-PubkeyHash
  new Buffer([0x02]), // SHA2 in Pay-to-Script-Hash multi-sig output (1 out of 2)
  new Buffer([0x03]), // All Hashes in Pay-to-Script-Hash multi-sig outputs (1 out of 3)
  new Buffer([0x04]), // Low security issue no SHA2 for torrent data. SHA1 is always inside OP_RETURN in this case.
  new Buffer([0x05]), // No rules, no torrent, no meta data ( no one may add rules in the future, anyone can add metadata )
  new Buffer([0x06])  // No meta data (anyone can add rules and/or metadata  in the future)
];

function IssuanceEncoder(params) {
  if (!(this instanceof IssuanceEncoder)) {
    return new IssuanceEncoder(params);
  }
  if(params) {
    this.amount = params.amount;
    this.lockStatus = params.lockStatus;
    this.divisibility = params.divisibility;
    this.aggregationPolicy = params.aggregationPolicy;
    this.protocol = params.protocol;
    this.version = params.version;
    this.payments = params.payments || [];
    this.torrentHash = params.torrentHash;
    this.sha2 = params.sha2;
    this.payments = params.payments;
    this.noRules = params.noRules;
  }
}

IssuanceEncoder.prototype.encode = function(byteSize) {
  $.checkState(this.amount, 'Amount must be set');
  $.checkState(this.lockStatus, 'lockStatus must be set');
  $.checkState(this.aggregationPolicy, 'aggregationPolicy must be set');
  $.checkState(this.protocol, 'protocol must be set');
  $.checkState(this.version, 'version must be set');
  var opcode;
  var hash = new Buffer(0);
  var protocolBuf = new Buffer(assetUtils.padLeadingZeros(this.protocol.toString(16), 2), 'hex');
  var versionBuf = new Buffer([this.version]);
  var issueHeader = Buffer.concat([protocolBuf, versionBuf]);
  var amount = sffc.encode(this.amount);
  var payments = new Buffer(0);
  if (this.payments) {
    var bulkEncoder = new PaymentEncoder();
    payments = bulkEncoder.encodeBulk(this.payments);
  }
  var issueFlagsByte = new IssueFlagsEncoder({ divisibility: this.divisibility, lockStatus: this.lockStatus, aggregationPolicy: this.aggregationPolicy }).encode();
  var issueTail = Buffer.concat([amount, payments, issueFlagsByte]);
  var issueByteSize = issueHeader.length + issueTail.length + 1;

  if (issueByteSize > byteSize) throw new Error('Data code is bigger then the allowed byte size');
  if (!this.sha2) {
    if (this.torrentHash) {
      if (issueByteSize + this.torrentHash.length > byteSize) throw new Error('Can\'t fit Torrent Hash in byte size');
      return { codeBuffer: Buffer.concat([issueHeader, OP_CODES[4], this.torrentHash, issueTail]), leftover: [] };
    }
    opcode = this.noRules ? OP_CODES[5] : OP_CODES[6];
    return { codeBuffer: Buffer.concat([issueHeader, opcode, hash, issueTail]), leftover: [] };
  }
  if (!this.torrentHash) throw new Error('Torrent Hash is missing');
  var leftover = [this.torrentHash, this.sha2];

  opcode = OP_CODES[3];
  issueByteSize = issueByteSize + this.torrentHash.length;

  if (issueByteSize <= byteSize) {
    hash = Buffer.concat([hash, leftover.shift()]);
    opcode = OP_CODES[2];
    issueByteSize = issueByteSize + this.sha2.length;
  }
  if (issueByteSize <= byteSize) {
    hash = Buffer.concat([hash, leftover.shift()]);
    opcode = OP_CODES[1];
  }
  return { codeBuffer: Buffer.concat([issueHeader, opcode, hash, issueTail]), leftover: leftover };
}

IssuanceEncoder.prototype.decode = function(op_code_buffer) {
  var data = {};
  if (!Buffer.isBuffer(op_code_buffer)) {
    op_code_buffer = new Buffer(op_code_buffer, 'hex');
  }
  var byteSize = op_code_buffer.length;
  var lastByte = op_code_buffer.slice(-1);
  var issueTail = new IssueFlagsEncoder().decode(assetUtils.consumer(lastByte));
  data.divisibility = issueTail.divisibility;
  data.lockStatus = issueTail.lockStatus;
  data.aggregationPolicy = issueTail.aggregationPolicy;
  var consume = assetUtils.consumer(op_code_buffer.slice(0, byteSize - 1));
  data.protocol = parseInt(consume(2).toString('hex'), 16);
  data.version = parseInt(consume(1).toString('hex'), 16);
  data.multiSig = [];
  var opcode = consume(1);
  if (opcode[0] === OP_CODES[1][0]) {
    data.torrentHash = consume(20);
    data.sha2 = consume(32);
  } else if (opcode[0] === OP_CODES[2][0]) {
    data.torrentHash = consume(20);
    data.multiSig.push({'index': 1, 'hashType': 'sha2'});
  } else if (opcode[0] === OP_CODES[3][0]) {
    data.multiSig.push({'index': 1, 'hashType': 'sha2'});
    data.multiSig.push({'index': 2, 'hashType': 'torrentHash'});
  } else if (opcode[0] === OP_CODES[4][0]) {
    data.torrentHash = consume(20);
  } else if (opcode[0] === OP_CODES[5][0]) {
    data.noRules = true;
  } else if (opcode[0] === OP_CODES[6][0]) {
    data.noRules = false;
  } else {
    throw new Error('Unrecognized Code');
  }

  data.amount = assetUtils.decodeAmountByVersion(data.version, consume, data.divisibility);
  data.payments = new PaymentEncoder().decodeBulk(consume);
  return new IssuanceEncoder(data);
}

module.exports = IssuanceEncoder;