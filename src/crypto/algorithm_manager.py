from typing import Dict, List, Type, Optional
from .base_algorithm import BaseCryptoAlgorithm
from .caesar_cipher import CaesarCipher
from .vigenere_cipher import VigenereCipher
from .beaufort_cipher import BeaufortCipher
from .chacha20_cipher import ChaCha20Cipher
from .aes.ecb_method import EcbMethod
from .aes.cbc_method import CbcMethod
from .aes.ctr_method import CtrMethod
from .aes.gcm_method import GcmMethod
from .rsa_cipher import RsaCipher
from .ecdh_key_exchange import ECDHKeyExchange

class AlgorithmManager:
    def __init__(self):
        self._algorithms: Dict[str, BaseCryptoAlgorithm] = {}
        self._register_default_algorithms()
    
    def _register_default_algorithms(self):
        self.register_algorithm(CaesarCipher())
        self.register_algorithm(VigenereCipher())
        self.register_algorithm(BeaufortCipher())   
        self.register_algorithm(ChaCha20Cipher())
        self.register_algorithm(EcbMethod())
        self.register_algorithm(CbcMethod())
        self.register_algorithm(CtrMethod())
        self.register_algorithm(GcmMethod())
        self.register_algorithm(RsaCipher())
        self.register_algorithm(ECDHKeyExchange())
    
    def register_algorithm(self, algorithm: BaseCryptoAlgorithm):
        self._algorithms[algorithm.name] = algorithm
    
    def get_algorithm(self, name: str) -> Optional[BaseCryptoAlgorithm]:
        return self._algorithms.get(name)
    
    def get_all_algorithms(self) -> List[BaseCryptoAlgorithm]:
        return list(self._algorithms.values())
    
    def get_algorithm_names(self) -> List[str]:
        return list(self._algorithms.keys())
