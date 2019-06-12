# DigiAsset
Represents a DigiAsset. DigiAssets are a way to encode transactions with specific instrustions. See [the official DigiAsset Wiki](https://digiassets.net) for further details.

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
console.log(tx);
```