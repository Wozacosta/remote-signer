# Tezos Remote Signer
This is a Python app that receives remote-signer protocol formatted messages from the Tezos baking client and passes them on to a Google Cloud Platform KMS CloudHSM to be signed.  It is based *heavily* on Blockscale's tacoinfra/remote-signer for AWS where  substitutions for GCP signing have been made. A usability improvement is that this script will autodetect all signing keys in your specified keyring and will allow for signing from clients by all keys.  It is *highly* recommended to make a tiny transction to and from your new HSM tz3 account before transferring a large amount to the new tz3 account.


## GCP Elements
* This was developed on an Ubuntu VM (python3 v 3.6.7) running the tezos code, configured with a service account json file specified in GOOGLE_APPLICATION_CREDENTIALS where this service account has appropriate get/list/signing permissions on the keyring/key.
* KMS with HSM-backed P256 key(s).  Always make sure the version for each key is 1.
* Only EC signing keys should be present in this particular vault; any other non-signing types of keys will cause failures.
* GCP currently only supports the SECP256R1 P256 tz3 key.  We expect they will at some point add support for the SECP256K1 P256K tz2 key.


## Security Notes
This returns the signature for valid payloads, after performing some checks:
* Is the message a valid payload?
* Is the message within a certain threshold of the head of the chain? Ensures you are signing valid blocks.
* Remote hosts can only sign blocks/endorsements.  Localhost (127.0.0.1) can sign anything.

## Installation
```
virtualenv venv
source venv/bin/activate
cd venv
git clone -b gcp_nonbigtable https://github.com/tezzigator/remote-signer.git
pip install -r requirements.txt
```

## Configure settings in the signer.py script
Python dict called 'config' at top of signer.py  - set the details of your GCP KMS here.

## Execution
```
FLASK_APP=signer flask run
```
or
```
nohup python3 -u signer.py &
```
Look in the remote-signer.log file and you will see all the pkhashes of all the keys that were detected from the keyring.
Use tezos-client to import those keys from the python signer.
