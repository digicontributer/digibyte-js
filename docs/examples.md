# DigiByte.JS examples

## Generate a random address
```javascript
var privateKey = new digibyte.PrivateKey();

var address = privateKey.toAddress();
```

## Generate a random legacy address
```javascript
var privateKey = new digibyte.PrivateKey();

var address = privateKey.toLegacyAddress();
```

## Generate a address from a SHA256 hash
```javascript
var value = new Buffer('correct horse battery staple');
var hash = digibyte.crypto.Hash.sha256(value);
var bn = digibyte.crypto.BN.fromBuffer(hash);

var address = new digibyte.PrivateKey(bn).toAddress();
```

## Import an address via WIF
```javascript
var wif = 'Kxr9tQED9H44gCmp6HAdmemAzU3n84H3dGkuWTKvE23JgHMW8gct';

var address = new digibyte.PrivateKey(wif).toAddress();
```

## Create a Transaction
```javascript
var privateKey = new digibyte.PrivateKey('L1uyy5qTuGrVXrmrsvHWHgVzW9kKdrp27wBC7Vs6nZDTF2BRUVwy');
var utxo = {
  "txId" : "115e8f72f39fad874cfab0deed11a80f24f967a84079fb56ddf53ea02e308986",
  "outputIndex" : 0,
  "address" : "dgb1qrrx8v0u65t5tnx84tfdlqwja0sq62840d4h7gy",
  "script" : "76a91447862fe165e6121af80d5dde1ecb478ed170565b88ac",
  "satoshis" : 50000
};

var transaction = new digibyte.Transaction()
  .from(utxo)
  .to('dgb1qz93rjfpk976zd2qal32d6zj7ctv9vywn9h7zdq', 15000)
  .sign(privateKey);
```

## Sign a DigiByte message
```javascript
var Message = require('digibyte-message');

var privateKey = new digibyte.PrivateKey('L23PpjkBQqpAF4vbMHNfTZAb3KFPBSawQ7KinFTzz7dxq6TZX8UA');
var message = new Message('This is an example of a signed message.');

var signature = message.sign(privateKey);
```

## Verify a DigiByte message
```javascript
var Message = require('digibyte-message');

var address = 'dgb1qz93rjfpk976zd2qal32d6zj7ctv9vywn9h7zdq';
var signature = 'IBOvIfsAs/da1e36W8kw1cQOPqPVXCW5zJgNQ5kI8m57FycZXdeFmeyoIqJSREzE4W7vfDmdmPk0HokuJPvgPPE=';

var verified = new Message('This is an example of a signed message.').verify(address, signature);
 ```

## Create an OP RETURN transaction
```javascript
var privateKey = new digibyte.PrivateKey('L1uyy5qTuGrVXrmrsvHWHgVzW9kKdrp27wBC7Vs6nZDTF2BRUVwy');
var utxo = {
  "txId" : "115e8f72f39fad874cfab0deed11a80f24f967a84079fb56ddf53ea02e308986",
  "outputIndex" : 0,
  "address" : "dgb1qrrx8v0u65t5tnx84tfdlqwja0sq62840d4h7gy",
  "script" : "76a91447862fe165e6121af80d5dde1ecb478ed170565b88ac",
  "satoshis" : 50000
};

var transaction = new digibyte.Transaction()
    .from(utxo)
    .addData('digibyte rocks') // Add OP_RETURN data
    .sign(privateKey);
```

## Create a 2-of-3 multisig P2SH address
```javascript
var publicKeys = [
  '026477115981fe981a6918a6297d9803c4dc04f328f22041bedff886bbc2962e01',
  '02c96db2302d19b43d4c69368babace7854cc84eb9e061cde51cfa77ca4a22b8b9',
  '03c6103b3b83e4a24a0e33a4df246ef11772f9992663db0c35759a5e2ebf68d8e9'
];
var requiredSignatures = 2;

var address = new digibyte.Address(publicKeys, requiredSignatures);
```

## Spend from a 2-of-2 multisig P2SH address
```javascript
var privateKeys = [
  new digibyte.PrivateKey('91avARGdfge8E4tZfYLoxeJ5sGBdNJQH4kvjJoQFacbgwmaKkrx'),
  new digibyte.PrivateKey('91avARGdfge8E4tZfYLoxeJ5sGBdNJQH4kvjJoQFacbgww7vXtT')
];
var publicKeys = privateKeys.map(digibyte.PublicKey);
var address = new digibyte.Address(publicKeys, 2); // 2 of 2

var utxo = {
  "txId" : "153068cdd81b73ec9d8dcce27f2c77ddda12dee3db424bff5cafdbe9f01c1756",
  "outputIndex" : 0,
  "address" : address.toString(),
  "script" : new digibyte.Script(address).toHex(),
  "satoshis" : 20000
};

var transaction = new digibyte.Transaction()
    .from(utxo, publicKeys, 2)
    .to('dgb1qrrx8v0u65t5tnx84tfdlqwja0sq62840d4h7gy', 20000)
    .sign(privateKeys);
```
