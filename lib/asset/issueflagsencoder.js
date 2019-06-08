'use strict';

var $ = require('../util/preconditions');
var assetUtils = require('../util/assets');

var aggregationPolicies = [
  'aggregatable',
  'hybrid',
  'dispersed'
]

function IssueFlagsEncoder(params) {
  if (!(this instanceof IssueFlagsEncoder)) {
    return new IssueFlagsEncoder(params);
  }
  if (!params) {
    return;
  }
  this.divisibility = params.divisibility;
  this.lockStatus = params.lockStatus;
  this.aggregationPolicy = params.aggregationPolicy || aggregationPolicies[0];
}

IssueFlagsEncoder.prototype.encode = function() {
  if (this.divisibility < 0 || this.divisibility > 7) throw new Error('Divisibility not in range');
  if ((this.aggregationPolicy = aggregationPolicies.indexOf(this.aggregationPolicy)) < 0) throw new Error('Invalid aggregation policy');
  var result = this.divisibility << 1;
  var lockStatusFlag = 0;
  this.lockStatus && (lockStatusFlag = 1);
  result = result | lockStatusFlag;
  result = result << 2;
  result = result | this.aggregationPolicy;
  result = result << 2;
  result = assetUtils.padLeadingZeros(result.toString(16), 1);
  return new Buffer(result, 'hex');
}

IssueFlagsEncoder.prototype.decode = function(consume) {
  var number = consume(1)[0];
  number = number >> 2;  // least significant 2 bits unused
  var aggregationPolicy = aggregationPolicies[number & 0x3];
  number = number >> 2;
  var lockStatus = !!(number & 1);
  number = number >> 1;
  var divisibility = (number & 0x7);
  return new IssueFlagsEncoder({ divisibility: divisibility, lockStatus: lockStatus, aggregationPolicy: aggregationPolicy });
}

module.exports = IssueFlagsEncoder;