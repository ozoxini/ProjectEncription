from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

class BaseCryptoAlgorithm(ABC):
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
    
    @abstractmethod
    def encrypt(self, data: bytes, key: Any) -> bytes:
        pass
    
    @abstractmethod
    def decrypt(self, data: bytes, key: Any) -> bytes:
        pass
    
    @abstractmethod
    def validate_key(self, key: Any) -> bool:
        pass
    
    def get_info(self) -> Dict[str, str]:
        return {
            "name": self.name,
            "description": self.description
        }