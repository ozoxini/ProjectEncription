from typing import Dict, List, Type, Optional
from .base_algorithm import BaseCryptoAlgorithm
from .caesar_cipher import CaesarCipher


class AlgorithmManager:
    def __init__(self):
        self._algorithms: Dict[str, BaseCryptoAlgorithm] = {}
        self._register_default_algorithms()
    
    def _register_default_algorithms(self):
        self.register_algorithm(CaesarCipher())
    
    def register_algorithm(self, algorithm: BaseCryptoAlgorithm):
        self._algorithms[algorithm.name] = algorithm
    
    def get_algorithm(self, name: str) -> Optional[BaseCryptoAlgorithm]:
        return self._algorithms.get(name)
    
    def get_all_algorithms(self) -> List[BaseCryptoAlgorithm]:
        return list(self._algorithms.values())
    
    def get_algorithm_names(self) -> List[str]:
        return list(self._algorithms.keys())