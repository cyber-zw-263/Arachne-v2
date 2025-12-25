import json
import os
from cryptography.fernet import Fernet
from base64 import b64encode, b64decode

class Vault:
    def __init__(self, vault_file='.arachne_keys', key_file='.master.key'):
        self.vault_file = vault_file
        self.key_file = key_file
        self.cipher = self._get_cipher()
    
    def _get_cipher(self):
        """Get or create encryption cipher."""
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                key = f.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(key)
            os.chmod(self.key_file, 0o600)
        return Fernet(key)
    
    def load_keys(self) -> dict:
        """Load and decrypt API keys."""
        if not os.path.exists(self.vault_file):
            return {}
        
        with open(self.vault_file, 'rb') as f:
            encrypted = f.read()
        
        try:
            decrypted = self.cipher.decrypt(encrypted)
            return json.loads(decrypted.decode())
        except:
            print("Vault corrupted or wrong key.")
            return {}
    
    def save_keys(self, keys: dict):
        """Encrypt and save API keys."""
        data = json.dumps(keys).encode()
        encrypted = self.cipher.encrypt(data)
        
        with open(self.vault_file, 'wb') as f:
            f.write(encrypted)
        os.chmod(self.vault_file, 0o600)
    
    def add_key(self, service: str, key: str):
        """Add a single key to the vault."""
        keys = self.load_keys()
        keys[service] = key
        self.save_keys(keys)