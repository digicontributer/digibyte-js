'use strict';

var _ = require('lodash');
var rsa = require('node-rsa');
var $ = require('../util/preconditions');
var assetUtils = require('../util/assets');
var Base58Check = require('../encoding/base58check');
var bn = require('../crypto/bn');
var BufferUtil = require('../util/buffer');
var Hash = require('../crypto/hash');
var Address = require('../address');
var OpCode = require('../opcode');
var Script = require('../script');
var Transaction = require('../transaction');
var Unit = require('../unit');

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

var padLeadingZeros = function (hex, byteSize) {
  if (!byteSize) {
    byteSize = Math.ceil(hex.length / 2)
  }
  return (hex.length === byteSize * 2) ? hex : padLeadingZeros('0' + hex, byteSize)
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
  if(data) {
    this.aggregationPolicy = data.aggregationPolicy || 'aggregatable';
    this.assetId =  data.assetId || '';
    this.type = data.type || undefined;
    this.lockStatus = data.lockStatus || true;
    this.multiSig = data.multiSig || [];
    this.payments = data.payments || [];
    this.amount = data.amount;
    this.issueAddress = data.issueAddress;
    this.to = data.to;
    this.from = data.from;
    this.burn = data.burn;
    this.protocol = data.protocol || Asset.ASSET_IDENTIFIER;
    this.version = data.version || Asset.DA_TX_VERSION;
    this.divisibility = data.divisibility || 0;
    this.urls = data.urls || [];
    this.transfer = data.transfer || [];
    this.metadata = data.metadata;
    this.rules = data.rules || [];
    this.falgs = data.flags;
    this.fee = data.fee;
    this.financeOutput = data.financeOutput;
    this.financeOutputTxid = data.financeOutputTxid;
    this.sha1 = data.sha1;
    this.sha2 = data.sha2;
    this.ignoreMetadata = data.ignoreMetadata || false;
  }
  if(!this.type) {
    this.fromBuffer(data);
  }
}

Asset.MIN_FEE = 1000;
Asset.DA_TX_VERSION = 0x02;
Asset.ASSET_IDENTIFIER = 0x4441;
Asset.MAXBYTESIZE = 80;

/**
 * Converts asset from OP_Return buffer
 *
 * @param {Object} data
 * @return {Asset}
 */
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

/**
 * Sets the asset amount
 *
 * @param {Number} amount
 * @param {Number} divisibility
 */
Asset.prototype.setAmount = function(amount, divisibility) {
  $.checkState(amount , 'Amount must be set');
  this.type = 'issuance';
  this.divisibility = divisibility || 0;
  this.amount = amount;
}

/**
 * Sets the asset lock status
 *
 * @param {Boolean} lockStatus
 */
Asset.prototype.setLockStatus = function(lockStatus) {
  this.lockStatus = lockStatus;
  this.type = 'issuance';
}

/**
 * Sets the asset aggregation policy
 *
 * @param {String} aggregationPolicy
 */
Asset.prototype.setAggregationPolicy = function(aggregationPolicy) {
  this.aggregationPolicy = aggregationPolicy || 'aggregatable';
  this.type = 'issuance';
}

/**
 * Sets the asset torrent hash
 *
 * @param {String} torrentHash
 * @param {String} sha2
 */
Asset.prototype.setHash = function(torrentHash, sha2) {
  if (!torrentHash) throw new Error('Can\'t set hashes without the torrent hash');
  if (!Buffer.isBuffer(torrentHash)) {
    torrentHash = new Buffer(torrentHash, 'hex');
  }
  this.torrentHash = torrentHash;
  if (sha2) {
    if (!Buffer.isBuffer(sha2)) {
      sha2 = new Buffer(sha2, 'hex');
    }
    this.sha2 = sha2;
  }
}

/**
 * Sets the asset noRules var
 *
 */
Asset.prototype.allowRules = function() {
  this.noRules = false;
}

/**
 * Gets the AssetID 
 *
 * @param {Input} firstInput
 */
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

/**
 * Creates AssetID from txid and input index
 *
 * @param {Input} firstInput
 * @param {Number} padding
 */
Asset.prototype.createIdFromTxidIndex = function(firstInput, padding) {
  var str = firstInput.prevTxId + ':' + firstInput.outputIndex;
  this.assetId = this.hashAndBase58CheckEncode(Buffer.from(str), padding);
  return this.assetId;
};

/**
 * Creates AssetId from pubkey hash
 *
 * @param {Script} script
 * @param {Number} padding
 */
Asset.prototype.createIdFromPubKeyHashInput = function(script, padding) {
  var Script = require('../script');
  var pubKeyHash = new Address(Hash.sha256ripemd160(script.chunks[1].buf));
  var pubKeyHashOutput = Script.buildPublicKeyHashOut(pubKeyHash).toBuffer();
  this.assetId = this.hashAndBase58CheckEncode(pubKeyHashOutput, padding);
  return this.assetId;
};

/**
 * Hash and base58 encode the assetID
 *
 * @param {String} payloadToHash
 * @param {Number} padding
 */
Asset.prototype.hashAndBase58CheckEncode = function(payloadToHash, padding) {
  var hash256 = Hash.sha256(payloadToHash);
  var hash160 = Hash.ripemd160(hash256);
  padding = new Buffer(padLeadingZeros(padding.toString(16)), 'hex');
  var divisibility = new Buffer(padLeadingZeros(this.divisibility.toString(16), POSTFIXBYTELENGTH), 'hex');
  var concatenation = Buffer.concat([padding, hash160, divisibility]);
  return Base58Check.encode(concatenation);;
};

/**
 * Encode the asset
 *
 */
Asset.prototype.encode = function() {
  var encoder = OP_CODES[this.type];
  this.payments = paymentsInputToSkip(this.payments);
  var result = new encoder.encoder(this).encode(Asset.MAXBYTESIZE);
  this.payments = paymentsSkipToInput(this.payments);
  return result;
};

/**
 * Adds a payment to the asset
 *
 * @param {Input} input
 * @param {Number} amount
 * @param {Number} output
 * @param {Number} range
 * @param {Number} percent
 */
Asset.prototype.addPayment  = function(input, amount, output, range, percent) {
  var range = range || false;
  var percent = percent || false;
  this.payments.push({input: input, amount: amount, output: output, range: range, percent: percent});
};

/**
 * Adds a burn payment to the asset
 *
 * @param {Input} input
 * @param {Number} amount
 * @param {Number} percent
 */
Asset.prototype.addBurn = function (input, amount, percent) {
  if (this.type === 'issuance') {
    throw new Error('Can\'t add burn payment to an issuance transaction')
  }
  this.payments.push({ input: input, amount: amount, percent: percent, burn: true });
  this.type = 'burn';
}

/**
 * Encrypts the asset data
 *
 * @param {Object} assetData
 */
Asset.prototype.tryEncryptData = function (assetData) {
  try {
    if(assetData.metadata && assetData.metadata.encryptions && assetData.metadata.userData) {
      var oneKey = new rsa({b: 1024})
      var returnKey = false
      assetData.metadata.encryptions.forEach(function (encSection){
          returnKey = returnKey || !encSection.pubKey
          var section = assetData.metadata.userData[encSection.key]
          if(section) {
              var format = encSection.type + '-public-' +  encSection.format;
              var key = encSection.pubKey ? new rsa([encSection.pubKey]) : oneKey;
              var encrypted = key.encrypt(section, 'base64');
              assetData.metadata.userData[encSection.key] = encrypted;
          }
       });
       return { privateKey: returnKey ? oneKey.exportKey('pkcs8').toString('hex') : '' };
    }
  } catch (e) {
    return e;
  }
}

/**
 * Gets the metadata
 *
 */
Asset.prototype.getMetaData = function() {
  var metafile = {};
  if(this.metadata) {
    var key = this.tryEncryptData();
    if (key && key.error) {
      throw new Error('Encryption error: ' + key.error);
    } else if (key && key.privateKey) {
      this.privateKey = key.privateKey;
    }
    metafile.data = this.metadata;
    if(this.rules) {
      metafile.rules = this.rules;
    }
  }
  return metafile;
}

/**
 * Finds the best matching utxos containg assets
 *
 * @param {Array} utxos
 * @param {Array} assetList
 * @param {String} key
 * @param {Transaction} tx
 * @param {Object} inputvalues
 * @param {Object} medata
 * @return {String} fee
 */
Asset.prototype.findBestMatchByNeededAssets = function(utxos, assetList, key, tx, inputvalues) {
  var self = this;
  var selectedUtxos = [];
  var foundAmount = 0;

  var bestGreaterOrEqualAmountUtxo = this.findBestGreaterOrEqualAmountUtxo(utxos, assetList, key);
  if (bestGreaterOrEqualAmountUtxo) {
    selectedUtxos[0] = bestGreaterOrEqualAmountUtxo;
  } else {
    var utxosSortedByAssetAmount = _.sortBy(utxos, function (utxo) { return -self.getUtxoAssetAmount(utxo, key) });
    var found = utxosSortedByAssetAmount.some(function (utxo) {
      selectedUtxos.push(utxo);
      foundAmount += self.getUtxoAssetAmount(utxo, key);
      return foundAmount >= assetList[key].amount;
    });
    if (!found) {
      selectedUtxos.length = 0;
    }
  }

  if (!selectedUtxos.length) {
    return false;
  }

  var lastAssetId;
  selectedUtxos.some(function (utxo) {
    utxo.assets.forEach(function (asset) {
      try {
        var overflow = true;
        if (assetList[asset.assetId] && !assetList[asset.assetId].done) {
          var inputIndex = tx.inputs.length
          if (!tx.inputs.some(function (txutxo, i) {
            if (txutxo.index === utxo.index && BufferUtil.reverse(txutxo.hash).toString('hex') === utxo.txid) {
              inputIndex = i;
              return true
            }
            return false
          })) {
            var output = new Transaction.UnspentOutput({
              address: utxo.address,
              txid: utxo.txid,
              vout: utxo.index,
              scriptPubKey: utxo.scriptPubKey.hex,
              amount: utxo.value,
            });
            tx.from(output);
            inputvalues.amount += Math.round(utxo.value);
            if (self.flags && self.flags.injectPreviousOutput) {
              tx.inputs[tx.inputs.length - 1].script = Script.fromHex(utxo.scriptPubKey.hex)
            }
          }

          var aggregationPolicy = asset.aggregationPolicy || 'aggregatable';  // TODO - remove after all assets have this field
          var inputIndexInAsset = assetList[asset.assetId].inputs.length;
          if (assetList[asset.assetId].amount <= asset.amount) {
            var totalamount = asset.amount;
            if (aggregationPolicy === 'aggregatable' && lastAssetId === asset.assetId && assetList[asset.assetId].inputs.length) {
              assetList[asset.assetId].inputs[inputIndexInAsset - 1].amount += assetList[asset.assetId].amount;
            } else {
              assetList[asset.assetId].inputs.push({index: inputIndex, amount: assetList[asset.assetId].amount});
            }
            assetList[asset.assetId].change = totalamount - assetList[asset.assetId].amount;
            assetList[asset.assetId].done = true;
          } else {
            if (aggregationPolicy === 'aggregatable' && lastAssetId === asset.assetId && assetList[asset.assetId].inputs.length) {
              assetList[asset.assetId].inputs[inputIndexInAsset - 1].amount += asset.amount;
            } else {
              assetList[asset.assetId].inputs.push({index: inputIndex, amount: asset.amount});
            }
            assetList[asset.assetId].amount -= asset.amount;
          }
        }
      } catch (e) { throw e; }
      
      lastAssetId = asset.assetId;
    });
    return assetList[key].done;
  });
  return true;
}

/**
 * Finds the best utxo matching a key
 *
 * @param {Array} utxos
 * @param {Array} assetList
 * @param {String} key
 * @return {Boolean}
 */
Asset.prototype.findBestGreaterOrEqualAmountUtxo = function (utxos, assetList, key) {
  var foundLargerOrEqualAmountUtxo = false;
  var self = this;

  utxos.forEach(function (utxo) {
    utxo.score = 0;
    var assetAmount = self.getUtxoAssetAmount(utxo, key);
    if (assetAmount < assetList[key].amount) {
      return;
    }
    foundLargerOrEqualAmountUtxo = true;
    if (assetAmount === assetList[key].amount) {
      utxo.score += 10000;
    } else {  // assetAmount > assetList[key].amount
      utxo.score += 1000;
    }

    for (var assetId in assetList) {
      if (assetId === key) continue;
      assetAmount = self.getUtxoAssetAmount(utxo, assetId);
      if (assetAmount === assetList[assetId].amount) {
        utxo.score += 100;
      } else if (assetAmount > assetList[assetId].amount) {
        utxo.score += 10;
      } else {  // assetAmount < assetList[assetId].amount
        utxo.score += assetAmount / assetList[assetId].amount;
      }
    }
  });
  return foundLargerOrEqualAmountUtxo && _.maxBy(utxos, function (utxo) { return utxo.score });
}

/**
 * Inserts digitoshi into the current transaction
 *
 * @param {Array} utxos
 * @param {Transaction} tx
 * @param {Number} missing
 * @param {Number} inputsValue
 */
Asset.prototype.insertSatoshiToTransaction = function(utxos, tx, missing, inputsValue) {
  var self = this;
  var paymentDone = false;
  var missingbn = new bn(missing);
  var financeValue = new bn(0);
  var currentAmount = new bn(0);
  if(self.financeOutput && self.financeOutputTxid) {
    if(self.isInputInTx(tx, self.financeOutputTxid, self.financeOutput.n)) {
      return false;
    }
    financeValue = new bn(self.financeOutput.value);
    if(financeValue.minus(missingbn) >= 0) {
      //TODO: check there is no asset here
      tx.addInput( self.financeOutputTxid, self.financeOutput.n);
      inputsValue.amount += financeValue.toNumber() ;
      if( self.flags && self.flags.injectPreviousOutput) {
        tx.inputs[tx.inputs.length -1].script = Script.fromHex(self.financeOutput.scriptPubKey.hex);
      }  
      paymentDone = true;
      return paymentDone;
    }
  } else {
    var hasEnoughEquity = utxos.some(function (utxo) {
      utxo.value = Math.round(utxo.value)
        if (!self.isInputInTx(tx, utxo.txid, utxo.index) && !(utxo.assets && utxo.assets.length)) {
          var output = new Transaction.UnspentOutput({
            address: utxo.address,
            txid: utxo.txid,
            vout: utxo.index,
            scriptPubKey: utxo.scriptPubKey.hex,
            amount: Unit.fromSatoshis(utxo.value).toDGB(),
          });
          tx.from(output);
          inputsValue.amount += utxo.value;
          currentAmount = currentAmount.add(new bn(utxo.value));
          if(self.flags && self.flags.injectPreviousOutput) {
            tx.inputs[tx.inputs.length -1].script = Script.fromHex(utxo.scriptPubKey.hex);
          }  
        }
        return currentAmount.cmp(missingbn) >= 0;
    });
    return hasEnoughEquity;
  }
}

/**
 * Gets the value from a utxo
 *
 * @param {UnspentOutput} utxo
 * @param {String} assetId
 */
Asset.prototype.getUtxoAssetAmount = function(utxo, assetId) {
  return _(utxo.assets).filter(function (asset) { return asset.assetId === assetId }).sumBy('amount');
}

/**
 * Adds enough inputs to fulfull the fee requirement
 *
 * @param {Transaction} tx
 * @param {Array} utxos
 * @param {Number} totalInputs
 * @param {Number} satoshiCost
 */
Asset.prototype.tryAddingInputsForFee = function(tx, utxos,  totalInputs, satoshiCost) {
  if(satoshiCost > totalInputs.amount) {
    if(!this.insertSatoshiToTransaction(utxos, tx, (satoshiCost - totalInputs.amount), totalInputs)) {
      return false;
    }
  }
  return true;
}

/**
 * Is this input already in the tx
 *
 * @param {Transaction} tx
 * @param {String} txid
 * @param {Number} index
 */
Asset.prototype.isInputInTx = function(tx, txid, index) {
  return tx.inputs.some(function (input) {
    var id = BufferUtil.reverse(input.prevTxId);
    return (id.toString('hex') === txid && input.index === index);
  });
}

/**
 * Gets the total Cost of the issuance transactions
 *
 * @param {Object} metaobj
 * @param {Boolean} withFee 
 * @return {Number} fee
 */
Asset.prototype.getTotalIssuenceCost = function(withFee) {
  var fee = withFee ? Asset.MIN_FEE : 0;
  if(this.transfer && this.transfer.length) {
    this.transfer.forEach(function(to) {
      fee += Transaction.DUST_AMOUNT;
    });
  }
  if(this.rules || this.metadata) {
    fee += 700; // MULTISIG_MIN_DUST
  }
  fee += Transaction.DUST_AMOUNT;
  return fee;
}

/**
 * Gets Issuance cost
 *
 */
Asset.prototype.getIssuenceCost = function() {
  return this.getTotalIssuenceCost(true); 
}

/**
 * Computes the cost of the transaction
 *
 * @param {Boolean} withFee
 */
Asset.prototype.comupteCost = function(withFee) {
  var fee = withFee ? (this.fee || Asset.MIN_FEE) : 0;

  if(this.to && this.to.length) {
    this.to.forEach(function(to) {
      fee += Transaction.DUST_AMOUNT;
    });
  }
  if(this.rules || this.metadata) {
    fee += 700;
  }
  fee += Transaction.DUST_AMOUNT;
  return fee;
}

/**
 * Gets the transaction change
 *
 * @param {Transaction} tx
 * @param {Number} totalInputValue
 */
Asset.prototype.getChangeAmount = function(tx, totalInputValue) {
  var allOutputValues =  _.sumBy(tx.outputs, function(output) { return output.toObject().satoshis; });
  return  (totalInputValue.amount - (allOutputValues + this.fee));
}

Asset.prototype.getNoneMinDustByScript = function(script, useFee) {
  varfee = useFee || Transaction.FEE_PER_KB;
  // add 9 to aacount for bitcoind SER_DISK serilaztion before the multiplication
  return (((Transaction.FEE_PER_KB * (script.toBuffer().length + 148 + 9 )) / 1000) * 3);
}

Asset.prototype.getInputAmountNeededForTx = function(tx, fee) {
  var total = fee || Transaction.FEE_PER_KB;
  tx.outputs.forEach(function(output){
    total += this.getNoneMinDustByScript(output.script, fee);
  });
  return total;
}

/**
 * Adds inputs to the asset transfer transaction.
 *
 * @param {Transaction} tx
 * @param {Object} assetData 
 * @param {Array} utxos
 * @return {Object} fee
 */
Asset.prototype.addInputsForSendTransaction = function(tx, utxos) {
  var self = this;
  var assetList = [];
  var totalInputs = { amount: 0 };
  var satoshiCost = this.comupteCost(true);
  var coloredOutputIndexes = [];
  var reedemScripts = [];
  self.to.forEach(function(to) {
    if(!assetList[to.assetId]) {
      assetList[to.assetId] = { amount: 0, addresses: [], done: false, change: 0, encodeAmount: 0, inputs: [] };
    }
    assetList[to.assetId].amount += to.amount;
    if (to.burn) {
      assetList[to.assetId].addresses.push({ address: 'burn', amount: to.amount });
    } else if (!to.address && to.pubKeys && to.m) {
      // ToDo
      var multisig = generateMultisigAddress(to.pubKeys, to.m)
      assetList[to.assetId].addresses.push({ address: multisig.address, amount: to.amount, reedemScript: multisig.reedemScript})
    } else {
      assetList[to.assetId].addresses.push({ address: to.address, amount: to.amount});
    }
 });
 for( var asset in assetList) {
  var assetUtxos = utxos.filter(function (element, index, array) {
    if (!element.assets) { return false; }                 
    return element.assets.some(function(a){
      return (a.assetId == asset);
    });
  });
  if(assetUtxos && assetUtxos.length > 0) {
    var key = asset;
    assetUtxos.forEach(function (utxo){ 
      if(utxo.used) {
        throw new Error('Output Alreaedy Spent - output: ' + utxo.txid + ':' + utxo.index);
      }
    });
    if(!self.findBestMatchByNeededAssets(assetUtxos, assetList, key, tx, totalInputs)) {
      throw new Error('Not enough assets - asset: ' + key);
    }
  } else {
    throw new Error('No output with that asset - asset: ' + asset);
  }
 }
 if(!self.tryAddingInputsForFee(tx, utxos, totalInputs, satoshiCost)) {
   throw new Error('Not enough funds');
 }
 for( asset in assetList) {
    var currentAsset = assetList[asset];
    if(!currentAsset.done) {
      return new Error('Not enough Assets - asset: ' + asset);
    }
    var uniAssets = _.uniqBy(currentAsset.addresses, function(item) { return item.address; } );
    uniAssets.forEach(function(address) {
      var addressAmountLeft = address.amount;
      currentAsset.inputs.some(function (input) {
        if(!input.amount) { return false; }
        if(addressAmountLeft - input.amount > 0 ) {
            if (address.address === 'burn') {
              self.addBurn(input.index, input.amount);
            } else {
              self.addPayment(input.index, input.amount, (tx.outputs ? tx.outputs.length : 0));
            }
            addressAmountLeft -= input.amount;
            input.amount = 0;
            return false;
        } else {
            if (address.address === 'burn') {
              self.addBurn(input.index, addressAmountLeft);
            } else {
              self.addPayment(input.index, addressAmountLeft, (tx.outputs ? tx.outputs.length : 0));
            }
            input.amount -= addressAmountLeft;
            addressAmountLeft = 0;
            return true;
        }
      });
      if (address.address !== 'burn') {
        tx.to(address.address, Transaction.DUST_AMOUNT);
      }
      if(address.reedemScript) {
        reedemScripts.push({index: tx.outputs.length -1, reedemScript: address.reedemScript, address: address.address});
      }
    });
  }
  try {
    //add metadata if we have any
    if((self.metadata || self.rules) && !self.ignoreMetadata) {
      if(!self.sha1 || !self.sha2) {
        throw new Error('Missing Torrenthash!');
      }
      self.setHash(self.sha1, self.sha2);
    }
    var buffer = self.encode();
    if(buffer.leftover && buffer.leftover.length > 0) {
      self.shiftOutputs();
      reedemScripts.forEach(function(item) { item.index += 1 });
      buffer = self.encode();
      if(buffer.leftover.length == 1) {
        //To Do
        addHashesOutput(tx, self.pubKeyReturnMultisigDust, buffer.leftover[0]);
      } else if(buffer.leftover.length == 2) {
        addHashesOutput(tx, self.pubKeyReturnMultisigDust, buffer.leftover[1], buffer.leftover[0]);
      } else {
        throw new Error('have hashes and enough room we offested inputs for nothing');
      }
    }
    // add array of colored ouput indexes
    self.payments.forEach(function (payment) {
      if (typeof payment.output !== 'undefined') {
        coloredOutputIndexes.push(payment.output);
      }
    }); 
  } catch(e) {
    throw e;
  }
  tx.addData(buffer.codeBuffer);
  var lastOutputValue = self.getChangeAmount(tx, totalInputs);
  var coloredChange = _.keys(assetList).some(function (assetId) {
    return assetList[assetId].change > 0;
  });
  var numOfChanges = (self.flags && self.flags.splitChange && coloredChange && lastOutputValue >= 2 * Transaction.DUST_AMOUNT) ? 2 : 1;
  if(lastOutputValue < numOfChanges * Transaction.DUST_AMOUNT) {
    satoshiCost = self.getInputAmountNeededForTx(tx, self.fee) + numOfChanges * Transaction.DUST_AMOUNT;
    if(!self.tryAddingInputsForFee(tx, utxos, totalInputs, satoshiCost)) {
      throw new Error('Not Enough funds');
    }
    lastOutputValue = self.getChangeAmount(tx, totalInputs);
  }
  // TODO: make sure we have a from here, even though we try to use first address found in the utxo we want to send
  // in case we didnt just use an address, there still might not be an address perhaps we should generate a keypair
  // here and return them as well, also we might have mutiple from addresses
  if (numOfChanges === 2) {
    tx.addOutput(Array.isArray(self.from) ? self.from[0] : self.from, lastOutputValue - Transaction.DUST_AMOUNT); 
    lastOutputValue = Transaction.DUST_AMOUNT;
  }
  if (coloredChange) {
    coloredOutputIndexes.push(tx.outputs.length)
  }
  tx.to(self.from, lastOutputValue);
  return { tx: tx, multisigOutputs: reedemScripts, coloredOutputIndexes: _.uniqBy(coloredOutputIndexes) };
}

/**
 * Adds inputs to the asset issue transaction.
 *
 * @param {Transaction} tx
 * @param {Array} utxos
 * @return {Object} object
 */
Asset.prototype.addInputsForIssuance = function(tx, utxos) {
  var current = new bn(utxos[0].value);
  if(utxos.length > 1) {
    var values = utxos.map(function(utxo) { return utxo.value; });
    current = new bn(values.reduce(function(a, b) { return a + b; }));
  }
  var cost = new bn(this.getIssuenceCost());
  var outputs = utxos.map(function(utxo) {
    return new Transaction.UnspentOutput({
      address: utxo.address,
      txid: utxo.txid,
      vout: utxo.index,
      scriptPubKey: utxo.scriptPubKey.hex,
      amount: utxo.value,
    });
  });
  tx.from(outputs);
  if(this.flags && this.flags.injectPreviousOutput) {
    tx.inputs[tx.inputs.length -1].script = new Script(utxo.scriptPubKey);
  }
  this.assetId = this.getAssetId(tx.inputs[0]);
  this.change = current - cost;
  this.totalInputs = { amount: current };
  return { tx: tx, assetData: this, change: current - cost, totalInputs: { amount: current } };
}

/**
 * Creates a Burn Asset transfer transaction
 *
 * @param {Object} assetData 
 * @param {Array} utxos
 * @return {Transaction}
 */
Asset.prototype.createBurnAssetTransaction = function(utxos) {
  var to = this.to || [];
  var burn = this.burn || [];
  burn.forEach(function(burnItem) {
    burnItem.burn = true;
  });
  to.push.apply(to, burn);
  delete this.transfer;
  this.to = to;
  var lol = this.createSendAssetTransaction(utxos);
  return this.createSendAssetTransaction(utxos); //{ tx: txResponse.tx, asset: completeTx.assetId.assetId, metadata: metadata, multisigOutputs: txResponse.multisigOutputs, coloredOutputIndexes: txResponse.coloredOutputIndexes };
}


/**
 * Creates an Asset transfer transaction
 *
 * @param {Object} assetData 
 * @param {Array} utxos
 * @return {Transaction}
 */
Asset.prototype.createSendAssetTransaction = function(tx, utxos) {
  this.addInputsForSendTransaction(tx, utxos);
  return this;
}

/**
 * Creates an Asset issue transaction
 *
 * @param {Object} assetData 
 * @param {Array} utxos
 * @return {Transaction}
 */
Asset.prototype.createIssueTransaction = function(tx, utxos) {
  $.checkState(this.amount , 'Amount must be set');
  $.checkState(this.issueAddress , 'Need an Issue Address');
  $.checkState(this.metadata, 'no metadata');
  this.addInputsForIssuance(tx, utxos);
  
  return this;
}

/**
 * Encodes the DigiAsset Scheme and adds it to OP_RETURN output
 *
 * @param {Object} args 
 * @return {Object}
 */
Asset.prototype.encodeDigiAssetScheme = function(tx) {
  var addMultisig = false;
  var encoder = new Asset({ protocol: Asset.ASSET_IDENTIFIER, version: Asset.DA_TX_VERSION, type: 'issuance', divisibility: this.divisibility, protocol: 17473, version: 0x02 });
  var reedemScripts = [];
  var coloredOutputIndexes = [];
  var coloredAmount = this.amount;
  this.setLockStatus(!this.reissueable);
  this.setAmount(this.amount, this.divisibility);
  this.setAggregationPolicy(this.aggregationPolicy);
  if((this.metadata || this.rules) && !this.ignoreMetadata) {
    if(!this.sha1 || !this.sha2) {
      throw new Error('Missing SHA hash');
    }
    this.setHash(this.sha1, this.sha2);
  }

  if(this.transfer) {
    this.transfer.forEach(function(transferobj, i){
      this.addPayment(0, transferobj.amount, tx.outputs.length);
      coloredAmount -= transferobj.amount;
      // check multisig
      if(transferobj.pubKeys && transferobj.m) {
         var multisig = generateMultisigAddress(transferobj.pubKeys, transferobj.m);
         reedemScripts.push({index: tx.outputs.length , reedemScript: multisig.reedemScript, address: multisig.address});
         tx.addOutput(multisig.address, Transaction.DUST_AMOUNT);
      }
      else {
        tx.addOutput(transferobj.address, Transaction.DUST_AMOUNT);
      }
    });
  }

  if (coloredAmount < 0) {
    throw new Error('transferring more than issued');
  }

  var buffer = this.encode();

  if(buffer.leftover && buffer.leftover.length > 0) {
    this.shiftOutputs();
    buffer = this.encode();
    addMultisig = true;
    reedemScripts.forEach(function(item) { item.index +=1 });
  }
  tx.addData(buffer.codeBuffer);

  // add array of colored ouput indexes
  encoder.payments.forEach(function (payment) {
    coloredOutputIndexes.push(payment.output);
  });


  // need to encode hashes in first tx
  if(addMultisig) {
    if(buffer.leftover && buffer.leftover.length == 1) {
      addHashesOutput(tx, this.pubKeyReturnMultisigDust, buffer.leftover[0]);
    } else if(buffer.leftover && buffer.leftover.length == 2) {
      addHashesOutput(tx, this.pubKeyReturnMultisigDust, buffer.leftover[1], buffer.leftover[0]);
    } else {
      throw new Error('have hashes and enough room we offested inputs for nothing');
    }
  }

  var allOutputValues =  _.sumBy(tx.outputs, function(output) { return output.value; });
  var lastOutputValue = this.totalInputs.amount - (allOutputValues + this.fee);
  if(lastOutputValue < Transaction.DUST_AMOUNT) {
    var totalCost = Transaction.DUST_AMOUNT + this.totalInputs.amount.toNumber();
    throw new errors.NotEnoughFundsError({
      type: 'issuance',
      fee: metadata.fee,
      totalCost: totalCost,
      missing: Transaction.DUST_AMOUNT - lastOutputValue
    });
  }
  if (this.flags && this.flags.splitChange && lastOutputValue >= 2 * Transaction.DUST_AMOUNT && coloredAmount > 0) {
    var digibyteChange = lastOutputValue - Transaction.DUST_AMOUNT;
    lastOutputValue = Transaction.DUST_AMOUNT;
    tx.addOutput(metadata.issueAddress, digibyteChange);
  }
  if (coloredAmount > 0) {
    // there's a colored change output
    coloredOutputIndexes.push(tx.outputs.length);
  }
  tx.to(this.issueAddress, lastOutputValue ?  Math.abs(lastOutputValue) :  Math.abs(this.change));

  return this;
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