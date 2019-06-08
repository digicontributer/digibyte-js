'use strict';

var _ = require('lodash');
var $ = require('../util/preconditions');
var Base58Check = require('../encoding/base58check');
var bn = require('../crypto/bn');
var Hash = require('../crypto/hash');
var Address = require('../address');
var OpCode = require('../opcode');
var Script = require('../script');
var Transaction = require('../transaction');

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
    'encoder': require('./issuanceencoder')
  },
  'transfer': {
    'start': 0x10,
    'end': 0x1f,
    'encoder': require('./transferencoder')
  },
  'burn': {
    'start': 0x20,
    'end': 0x2f,
    'encoder': require('./transferencoder')
  }
}

var encodingLookup = {}

for (var transactionType in OP_CODES) {
  for (var j = OP_CODES[transactionType].start; j <= OP_CODES[transactionType].end; j++) {
    encodingLookup[j] = {};
    encodingLookup[j].encoder = OP_CODES[transactionType].encoder;
    encodingLookup[j].type = transactionType;
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
function Asset(data) {
  /* jshint maxcomplexity: 20 */
  /* jshint maxstatements: 20 */
  if (!(this instanceof Asset)) {
    return new Asset(data);
  }
  this.assetId = '';
  this.aggregationPolicy = 'aggregatable';
  this.divisibility = 0;
  this.lockStatus = true;
  this.type = undefined;
  if(data) {
    this.type = data.type;
    this.multiSig = data.multiSig || [];
    this.payments = data.payments || [];
    this.protocol = data.protocol;
    this.version = data.version;
    this.divisibility = data.divisibility || 0;
  }
  if(!this.type) {
    this.fromBuffer(data);
  }
}

Asset.MIN_FEE = 1000;
Asset.DA_TX_VERSION = 0x02;
Asset.ASSET_IDENTIFIER = 0x4441;
Asset.MAXBYTESIZE = 80;

Asset.prototype.fromBuffer = function(data) {
  var decoder = encodingLookup[data[3]];
  var rawData = new decoder.encoder().decode(data);
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

Asset.prototype.padLeadingZeros  = function(hex, byteSize) {
  if (!byteSize) {
    byteSize = Math.ceil(hex.length / 2);
  }
  return (hex.length === byteSize * 2) ? hex : this.padLeadingZeros('0' + hex, byteSize);
};

Asset.prototype.setAmount = function(amount, divisibility) {
  $.checkState(amount , 'Amount must be set');
  this.type = 'issuance';
  this.divisibility = divisibility || 0;
  this.amount = amount;
}

Asset.prototype.setLockStatus = function(lockStatus) {
  this.lockStatus = lockStatus;
  this.type = 'issuance';
}

Asset.prototype.setAggregationPolicy = function(aggregationPolicy) {
  this.aggregationPolicy = aggregationPolicy || 'aggregatable';
  this.type = 'issuance';
}

Asset.prototype.allowRules = function() {
  this.noRules = false;
}

Asset.prototype.getAssetId = function(firstInput) {
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

Asset.prototype.createIdFromTxidIndex = function(firstInput, padding) {
  var str = firstInput.prevTxId + ':' + firstInput.outputIndex;
  return this.hashAndBase58CheckEncode(Buffer.from(str), padding);
};

Asset.prototype.createIdFromPubKeyHashInput = function(script, padding) {
  var Script = require('../script');
  var pubKeyHash = new Address(Hash.sha256ripemd160(script.chunks[1].buf));
  var pubKeyHashOutput = Script.buildPublicKeyHashOut(pubKeyHash).toBuffer();
  return this.hashAndBase58CheckEncode(pubKeyHashOutput, padding)
};

Asset.prototype.hashAndBase58CheckEncode = function(payloadToHash, padding) {
  var hash256 = Hash.sha256(payloadToHash);
  var hash160 = Hash.ripemd160(hash256);
  padding = new Buffer(this.padLeadingZeros(padding.toString(16)), 'hex');
  var divisibility = new Buffer(this.padLeadingZeros(this.divisibility.toString(16), POSTFIXBYTELENGTH), 'hex');
  var concatenation = Buffer.concat([padding, hash160, divisibility]);
  this.assetId = Base58Check.encode(concatenation);
  return this;
};

Asset.prototype.encode = function() {
  var encoder = OP_CODES[this.type];
  this.payments = paymentsInputToSkip(this.payments);
  var result = new encoder.encoder(this).encode(Asset.MAXBYTESIZE);
  this.payments = paymentsSkipToInput(this.payments);
  return result;
};

Asset.encodeAssetIdInfo = function(reissueable, txid, nvout, hex, divisibility, aggregationPolicy) {
  var opts = {
    'dadata': [{
      'type': 'issuance',
      'lockStatus': !reissueable,
      'divisibility': divisibility,
      'aggregationPolicy': aggregationPolicy
    }],
    'vin': [{
      'txid': txid,
      'vout': nvout,
      'previousOutput': {
        'hex': hex 
      } 
    }]
  };
  var assetId = assetIdencoder(opts)
  return assetId
}

Asset.getTotalIssuenceCost = function(metaobj, withfee) {
  var fee = withfee ? Asset.MIN_FEE : 0;
  if(metaobj.transfer && metaobj.transfer.length) {
    metaobj.transfer.forEach(function(to) {
      fee += Transaction.DUST_AMOUNT;
    });
  }
  if(metaobj.rules || metaobj.metadata) {
    fee += 700; // MULTISIG_MIN_DUST
  }
  fee += Transaction.DUST_AMOUNT;
  return fee;
}

Asset.getIssuenceCost = function(metaobj) {
  return Asset.getTotalIssuenceCost(metaobj, true); 
}

Asset.addInputsForIssuance = function(tx, assetData, utxo) {
  var assetId = '';
  var current = new bn(utxo.value);
  var cost = new bn(Asset.getIssuenceCost(assetData));
  var output = new Transaction.UnspentOutput(utxo);
  tx.from(output);
  if(assetData.flags && assetData.flags.injectPreviousOutput) {
    tx.inputs[tx.inputs.length -1].script = new Script(utxo.scriptPubKey);
  }
  var asset = new Asset({
    reissueable: assetData.reissueable || false,
    divisibility: assetData.divisibility || 0,
    aggregationPolicy: assetData.aggregationPolicy,
    type: 'issuance',
    multiSig: []
  });
  var assetId = asset.getAssetId(tx.inputs[0]);
  return { tx: tx, assetData: assetData, change: current - cost, assetId: assetId, totalInputs: { amount: current } };
}

Asset.createIssueTransaction = function(assetData, utxo) {
  var tx = new Transaction();
  var completeTx = Asset.addInputsForIssuance(tx, assetData, utxo);
  var txResponse = Asset.encodeDigiAssetScheme(completeTx);
  return txResponse.tx; //{ tx: txResponse.tx, asset: completeTx.assetId.assetId, metadata: metadata, multisigOutputs: txResponse.multisigOutputs, coloredOutputIndexes: txResponse.coloredOutputIndexes };
}

Asset.encodeDigiAssetScheme = function(args) {
  var addMultisig = false;
  var metadata = args.assetData;
  var encoder = new Asset({ protocol: Asset.ASSET_IDENTIFIER, version: Asset.DA_TX_VERSION, type: 'issuance', divisibility: this.divisibility, protocol: 17473, version: 0x02 });
  var reedemScripts = [];
  var coloredOutputIndexes = [];
  var coloredAmount = metadata.amount;
  encoder.setLockStatus(!metadata.reissueable);
  encoder.setAmount(metadata.amount, metadata.divisibility);
  encoder.setAggregationPolicy(metadata.aggregationPolicy);
  if(metadata.metadata || metadata.rules) {
     if(config.writemultisig) {
        if(!metadata.sha1 || !metadata.sha2) {
           throw new errors.MetadataMissingShaError()
        }
        encoder.setHash(metadata.sha1, metadata.sha2);
     }
  }

  if(metadata.transfer) {
    metadata.transfer.forEach(function(transferobj, i){
      encoder.addPayment(0, transferobj.amount, args.tx.outs.length);
      coloredAmount -= transferobj.amount;
      // check multisig
      if(transferobj.pubKeys && transferobj.m) {
         var multisig = generateMultisigAddress(transferobj.pubKeys, transferobj.m);
         reedemScripts.push({index: args.tx.outs.length , reedemScript: multisig.reedemScript, address: multisig.address});
         args.tx.addOutput(multisig.address, Transaction.DUST_AMOUNT);
      }
      else {
        args.tx.addOutput(transferobj.address, Transaction.DUST_AMOUNT);
      }
    });
  }

  if (coloredAmount < 0) {
    throw new Error('transferring more than issued');
  }

  var buffer = encoder.encode()

  if(buffer.leftover && buffer.leftover.length > 0) {
    encoder.shiftOutputs();
    buffer = encoder.encode();
    addMultisig = true;
    reedemScripts.forEach(function(item) { item.index +=1 });
  }
  args.tx.addData(buffer.codeBuffer);

  // add array of colored ouput indexes
  encoder.payments.forEach(function (payment) {
    coloredOutputIndexes.push(payment.output);
  });


  // need to encode hashes in first tx
  if(addMultisig) {
    if(buffer.leftover && buffer.leftover.length == 1) {
      addHashesOutput(args.tx, metadata.pubKeyReturnMultisigDust, buffer.leftover[0]);
    } else if(buffer.leftover && buffer.leftover.length == 2) {
      addHashesOutput(args.tx, metadata.pubKeyReturnMultisigDust, buffer.leftover[1], buffer.leftover[0]);
    } else {
      throw new Error('have hashes and enough room we offested inputs for nothing');
    }
  }

  var allOutputValues =  _.sumBy(args.tx.outs, function(output) { return output.value; });
  var lastOutputValue = args.totalInputs.amount - (allOutputValues + metadata.fee);
  if(lastOutputValue < Transaction.DUST_AMOUNT) {
    var totalCost = Transaction.DUST_AMOUNT + args.totalInputs.amount.toNumber();
    throw new errors.NotEnoughFundsError({
      type: 'issuance',
      fee: metadata.fee,
      totalCost: totalCost,
      missing: Transaction.DUST_AMOUNT - lastOutputValue
    });
  }
  if (metadata.flags && metadata.flags.splitChange && lastOutputValue >= 2 * Transaction.DUST_AMOUNT && coloredAmount > 0) {
    var bitcoinChange = lastOutputValue - Transaction.DUST_AMOUNT;
    lastOutputValue = Transaction.DUST_AMOUNT;
    args.tx.addOutput(metadata.issueAddress, bitcoinChange);
  }
  if (coloredAmount > 0) {
    // there's a colored change output
    coloredOutputIndexes.push(args.tx.outputs.length);
  }
  args.tx.to(metadata.issueAddress, lastOutputValue ?  Math.abs(lastOutputValue) :  Math.abs(args.change));

  return { tx: args.tx, multisigOutputs: reedemScripts, coloredOutputIndexes: _.uniq(coloredOutputIndexes), asset: this };
}

/**
 * Provide an informative output when displaying this object in the console
 * @returns string
 */
Asset.prototype.inspect = function() {
  if(this.type === 'issuance') {
    return '<DigiAsset: assetId: ' + this.assetId + ', type: ' + this.type + ', amount: ' + this.amount + ', divisibility: ' + this.divisibility.toString(16) +
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
Asset.prototype.toString = function() {
  return this.txId + ':' + this.outputIndex;
};

/**
 * Deserialize an UnspentOutput from an object
 * @param {object|string} data
 * @return UnspentOutput
 */
Asset.fromObject = function(data) {
  return new Asset(data);
};

/**
 * Returns a plain object (no prototype or methods) with the associated info for this output
 * @return {object}
 */
Asset.prototype.toObject = Asset.prototype.toJSON = function toObject() {
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

module.exports = Asset;