# DigiAsset
Represents a DigiAsset. DigiAssets are a way to encode transactions with specific instructions. See [the official DigiAsset Wiki](https://digiassets.net) for further details.

## Creating An Issuance Asset
To create an issuance asset you need a funded DigiByte address with associated utxos pulled from (https://explorerapi.digiassets.net/api/getaddressutxos?address=).

```javascript
var tx = new Transaction();
var digiAsset = tx.createAssetIssuance(assetData, utxo);
```

The assetData object must include the following fields (issueAddress, amount, fee, metadata). metadata is an object containing custom metadata that you want included in the blockchain

```javascript
var assetData = {
  issueAddress: 'DHUdu2DMUUXAErkgx3v3v3cdDcFYxYiSXy',
  fee: 500,
  amount: 100,
  metadata: {
    assetName: 'Test Asset'
  }
};
```

From here you will need to extract the metafile and upload it to an instance of [DigiAsset-Metadata-Server](https://github.com/DigiByte-Core/DigiAssets-Metadata-Server)

```javascript
// POST metafile to digiassets-metadata-server
var metafile = digiAsset.getMetadata();
```

Once done you can set the SHA1 and SHA2 hash entries for the Asset and encode it to be ready for signing and sending!

 ```javascript
digiAsset.sha1 = torretdata.torrentHash;
digiAsset.sha2 = torretdata.sha2;
digiAsset.encodeDigiAssetScheme();
console.log('Transaction: ' + tx);
console.log('Asset: ' + digiAsset);
```

tx is now ready to be signed and broadcasted to the DigiByte Blockchain!

## Creating An Transfer Asset
Creating a transfer Asset requires associated utxos pulled from (https://explorerapi.digiassets.net/api/getaddressutxos?address=)

```javascript
var assetData = {
  from: 'DHUdu2DMUUXAErkgx3v3v3cdDcFYxYiSXy',
  fee: 500
  to: [{
    address: 'DRGNccq3quL9FqJuHcB1JEQVKRpvaqGenp',
    amount: 50,
    assetId: 'La4fdFUgMKAGbgwL4bVVgobn6dYc2Vs7kZkwei'
  }]
};
var tx = new Transaction();
var digiAsset = tx.createAssetTransfer(assetData, utxos);
console.log('Transaction: ' + tx);
console.log('Asset: ' + digiAsset);
```

tx is now ready to be signed and broadcasted to the DigiByte Blockchain!

## Creating An Burn Asset
Creating a burn Asset requires associated utxos pulled from (https://explorerapi.digiassets.net/api/getaddressutxos?address=)

```javascript
var assetData = {
  from: 'DRGNccq3quL9FqJuHcB1JEQVKRpvaqGenp',
  fee: 500
  to: [{
    burn: true,
    amount: 50,
    assetId: 'La4fdFUgMKAGbgwL4bVVgobn6dYc2Vs7kZkwei'
  }]
};
var tx = new Transaction();
var digiAsset = tx.createAssetBurn(assetData, utxos);
console.log('Transaction: ' + tx);
console.log('Asset: ' + digiAsset);
```

tx is now ready to be signed and broadcasted to the DigiByte Blockchain!