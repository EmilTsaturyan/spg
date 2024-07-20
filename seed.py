import json

from mnemonic import Mnemonic
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins
from bip_utils import Bip44Changes


# Function to generate a seed phrase
def generate_seed_phrase():
    mnemo = Mnemonic("english")
    return mnemo.generate(strength=128)


# Function to derive Bitcoin address from seed phrase
def derive_address(seed_phrase):
    # Generate seed from seed phrase
    seed_bytes = Bip39SeedGenerator(seed_phrase).Generate()
    
    # Generate BIP44 wallet
    bip44_mst = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
    
    # Generate first key pair (account 0, change 0, address 0)
    bip44_acc = bip44_mst.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
    address = bip44_acc.PublicKey().ToAddress()
    
    return address


# Function to check if the derived address matches any in the dataset
def check_address(derived_address, dataset):
    return derived_address in dataset


# Function to save keys to files
def save_keys(seed_phrase):
    # Derive address from seed phrase
    priv_key = derive_private_key(seed_phrase)
    pub_key = derive_public_key(seed_phrase)

    data = {
        'seed_phrase': seed_phrase,
        'private_key': priv_key,
        'public_key': pub_key
    }
    
    # Save private key
    with open('keys.json', 'w') as f:
        json.dump(data, f, indent=4)


# Function to derive private key (WIF) from seed phrase
def derive_private_key(seed_phrase):
    seed_bytes = Bip39SeedGenerator(seed_phrase).Generate()
    bip44_mst = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
    bip44_acc = bip44_mst.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
    priv_key_wif = bip44_acc.PrivateKey().ToWif()
    return priv_key_wif

# Function to derive public key (Hex) from seed phrase
def derive_public_key(seed_phrase):
    seed_bytes = Bip39SeedGenerator(seed_phrase).Generate()
    bip44_mst = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
    bip44_acc = bip44_mst.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
    pub_key_hex = bip44_acc.PublicKey().RawCompressed().ToHex()
    return pub_key_hex


# Load your dataset of addresses 
def load_dataset(filename='base.txt'):
    addresses = set()
    with open(filename, 'r') as f:
        for line in f:
            if line.startswith('1'):
                addresses.add(line.strip())
    return addresses


def print_attempt(seed_phrase, attempt, max_length):
    print(f'Wallet check: {seed_phrase:<{max_length}} | Attempt: {attempt}')


# Brute-force loop
def brute_force():
    dataset = load_dataset()
    attempts = 1
    max_length = 0

    while True:
        seed_phrase = generate_seed_phrase()
        derived_address = derive_address(seed_phrase)
        
        if check_address(derived_address, dataset):
            print(f"Match found for seed phrase: {seed_phrase}")
            save_keys(seed_phrase)
            break
        else:
            # Update maximum length
            max_length = max(max_length, len(seed_phrase))
            if attempts % 100 == 0:
                print(f'Attempt: {attempts}\t|\tWallet check: {seed_phrase}')

        attempts += 1


# Run the brute-force example
brute_force()
