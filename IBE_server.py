from charm.toolbox.pairinggroup import PairingGroup
from charm.schemes.ibenc.ibenc_bf01 import IBE_BonehFranklin
import json, os

group = PairingGroup('MNT224', secparam=1024)
ibe = IBE_BonehFranklin(group)

param_path = "params.json"
key_db_path = "key_store.json"

def setup_ibe():
    master_pub_key, master_sec_key = ibe.setup()
    with open(param_path, "w") as f:
        json.dump({
            "mpk": group.serialize(master_pub_key).hex(),
            "msk": group.serialize(master_sec_key).hex()
        }, f)

def extract_private_key(identity: str):
    # Load the IBE parameters from JSON file
    with open(param_path, "r") as f:
        data = json.load(f)
    # Deserialize the master secret key from its hex representation
    master_sec_key = group.deserialize(bytes.fromhex(data["msk"]))
    # Extract the private key for the specified identity
    sk_id = ibe.extract(master_sec_key, identity)
    # Return the extracted private key
    return sk_id

def store_key(identity: str, key: bytes):
    key_db = {}
    db = json.load(open(key_db_path))
    db[identity] = key.hex()
    with open(key_db_path, "w") as f:
        json.dump(db, f)

def get_key(identity: str):
    db = json.load(open(key_db_path))
    return group.deserialize(bytes.fromhex(db[identity]))
        