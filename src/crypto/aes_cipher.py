from abc import ABC, abstractmethod
from typing import Any, Union
import base64
from .base_algorithm import BaseCryptoAlgorithm


class AesCipher(BaseCryptoAlgorithm):
    
    def __init__(self):
        super().__init__(
            name="Szyfr AES",
            description="Wersja testowa alpha szyfru AES"
        )
        self.block_size = 16

    def validate_key(self, key: Any) -> bool:
        return isinstance(key, str) and len(key) > 0

    def encrypt(self, data: Union[str, bytes], key: Any) -> Union[str, bytes]:
        """Szyfruje dane. Jeśli podano str -> zwraca base64-encoded str.
        Jeśli podano bytes -> zwraca bytes (surowy szyfrogram)."""
        if not self.validate_key(key):
            raise ValueError("Nieprawidłowy klucz.")

        # Przygotuj wejście jako bytes
        return_text = False
        if isinstance(data, str):
            data_bytes = data.encode('utf-8')
            return_text = True
        elif isinstance(data, (bytes, bytearray)):
            data_bytes = bytes(data)
        else:
            raise TypeError("Dane do zaszyfrowania muszą być typu str lub bytes")

        key_bytes = self._prepare_key(key)

        padded_data = self._pad(data_bytes)

        encrypted_bytes = b''

        for i in range(0, len(padded_data), self.block_size):
            blok = padded_data[i : i + self.block_size]
            encrypted_bytes += self._szyfruj_blok(blok, key_bytes)

        if return_text:
            return base64.b64encode(encrypted_bytes).decode('utf-8')
        return encrypted_bytes

    def decrypt(self, data: Union[str, bytes], key: Any) -> Union[str, bytes]:
        """Deszyfruje dane. Jeśli podano base64 str (czyli str wynikowy z encrypt) ->
        zwraca odszyfrowany tekst jako str. Jeśli podano bytes -> zwraca bytes."""
        if not self.validate_key(key):
            raise ValueError("Nieprawidłowy klucz.")

        # Przygotuj zaszyfrowane bytes
        return_text = False
        if isinstance(data, str):
            try:
                enc_bytes = base64.b64decode(data)
                return_text = True
            except Exception:
                raise ValueError("Nieprawidłowy format danych wejściowych (oczekiwany base64 string)")
        elif isinstance(data, (bytes, bytearray)):
            enc_bytes = bytes(data)
        else:
            raise TypeError("Dane do odszyfrowania muszą być typu str lub bytes")

        key_bytes = self._prepare_key(key)

        decrypted_padded_bytes = b''

        for i in range(0, len(enc_bytes), self.block_size):
            blok = enc_bytes[i : i + self.block_size]
            decrypted_padded_bytes += self._deszyfruj_blok(blok, key_bytes)

        try:
            decrypted_bytes = self._unpad(decrypted_padded_bytes)
        except ValueError as e:
            raise ValueError(f"Błąd deszyfrowania: {e}. Zły klucz lub uszkodzone dane.")

        if return_text:
            return decrypted_bytes.decode('utf-8')
        return decrypted_bytes


    def _prepare_key(self, key_str: str) -> bytes:
        key_bytes = key_str.encode('utf-8')
        return key_bytes.ljust(self.block_size, b'\x00')[:self.block_size]

    def _pad(self, dane: bytes) -> bytes:
        ilosc_brakujaca = self.block_size - (len(dane) % self.block_size)
        bajt_dopelnienia = bytes([ilosc_brakujaca])
        return dane + bajt_dopelnienia * ilosc_brakujaca

    def _unpad(self, dane: bytes) -> bytes:
        if not dane:
            raise ValueError("Puste dane do od-dopełnienia.")
        ilosc_dopelnienia = dane[-1]
        if ilosc_dopelnienia > self.block_size or ilosc_dopelnienia == 0:
            raise ValueError("Błędna wartość dopełnienia.")
        if dane[-ilosc_dopelnienia:] != bytes([ilosc_dopelnienia]) * ilosc_dopelnienia:
            raise ValueError("Błędne bajty dopełnienia.")
        return dane[:-ilosc_dopelnienia]

    def _szyfruj_blok(self, blok_jawny: bytes, key_bytes: bytes) -> bytes:
        stan = list(blok_jawny)
        klucz_byte_1 = key_bytes[0]; klucz_byte_2 = key_bytes[1]
        stan = [b ^ klucz_byte_1 for b in stan] # Runda 0
        stan = [b ^ 0xFF for b in stan] # SubBytes
        stan = stan[1:] + stan[:1] # ShiftRows
        stan = [b ^ 0xAA for b in stan] # MixColumns
        stan = [b ^ klucz_byte_2 for b in stan] # Runda 1
        return bytes(stan)

    def _deszyfruj_blok(self, blok_szyfrogramu: bytes, key_bytes: bytes) -> bytes:
        stan = list(blok_szyfrogramu)
        klucz_byte_1 = key_bytes[0]; klucz_byte_2 = key_bytes[1]
        stan = [b ^ klucz_byte_2 for b in stan] # Odwr. Runda 1
        stan = [b ^ 0xAA for b in stan] # Odwr. MixColumns
        stan = stan[-1:] + stan[:-1] # Odwr. ShiftRows
        stan = [b ^ 0xFF for b in stan] # Odwr. SubBytes
        stan = [b ^ klucz_byte_1 for b in stan] # Odwr. Runda 0
        return bytes(stan)