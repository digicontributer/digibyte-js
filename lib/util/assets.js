var sffc = require('sffc-encoder');

module.exports = {
  consumer: function(buff) {
    var curr = 0
    return function consume (len) {
      return buff.slice(curr, curr += len)
    };
  },

  decodeAmountByVersion: function(version, consume, divisibility) {
    var decodedAmount = sffc.decode(consume);
    return (version == 0x01)? (decodedAmount / Math.pow(10, divisibility)) : decodedAmount;
  },

  padLeadingZeros: function(hex, byteSize) {
    return (hex.length === byteSize * 2) ? hex : this.padLeadingZeros('0' + hex, byteSize);
  }
}