#!/usr/bin/env python3
"""
Skrypt testowy dla aplikacji kryptograficznej
"""

import sys
import os
sys.path.append('.')

from src.crypto.algorithm_manager import AlgorithmManager
from src.crypto.caesar_cipher import CaesarCipher

def test_caesar_cipher():
    """Testuje szyfr Cezara"""
    print("=== Test Szyfru Cezara ===")
    
    cipher = CaesarCipher()
    print(f"Algorytm: {cipher.name}")
    print(f"Opis: {cipher.description}")
    
    # Test różnych kluczy
    test_cases = [
        ("Hello World", 3),
        ("Python Programming", 7),
        ("Kryptografia", -5),
        ("Test 123 !@#", 13)
    ]
    
    for text, key in test_cases:
        print(f"\nTekst: '{text}'")
        print(f"Klucz: {key}")
        
        # Sprawdź walidację klucza
        if not cipher.validate_key(key):
            print(f"❌ Nieprawidłowy klucz: {key}")
            continue
        
        # Szyfrowanie
        encrypted = cipher.encrypt(text, key)
        print(f"Zaszyfrowany: '{encrypted}'")
        
        # Deszyfrowanie
        decrypted = cipher.decrypt(encrypted, key)
        print(f"Deszyfrowany: '{decrypted}'")
        
        # Sprawdź poprawność
        success = text == decrypted
        print(f"✅ Poprawność: {success}")

def test_algorithm_manager():
    """Testuje menedżer algorytmów"""
    print("\n=== Test Menedżera Algorytmów ===")
    
    manager = AlgorithmManager()
    
    print(f"Dostępne algorytmy: {manager.get_algorithm_names()}")
    
    for name in manager.get_algorithm_names():
        algorithm = manager.get_algorithm(name)
        print(f"\nAlgorytm: {algorithm.name}")
        print(f"Opis: {algorithm.description}")
        
        # Test podstawowej funkcjonalności
        test_text = "Test"
        test_key = 5
        
        if algorithm.validate_key(test_key):
            encrypted = algorithm.encrypt(test_text, test_key)
            decrypted = algorithm.decrypt(encrypted, test_key)
            print(f"Test szyfrowania: '{test_text}' -> '{encrypted}' -> '{decrypted}'")
            print(f"✅ Poprawność: {test_text == decrypted}")
        else:
            print(f"❌ Nieprawidłowy klucz: {test_key}")

def test_file_operations():
    """Testuje operacje na plikach"""
    print("\n=== Test Operacji na Plikach ===")
    
    # Utwórz testowy plik
    test_file = "test_file.txt"
    test_content = "To jest testowy plik do szyfrowania.\nZawiera polskie znaki: ąćęłńóśźż\nI cyfry: 123456789"
    
    try:
        # Zapisz testowy plik
        with open(test_file, 'w', encoding='utf-8') as f:
            f.write(test_content)
        print(f"✅ Utworzono plik testowy: {test_file}")
        
        # Test szyfrowania pliku
        manager = AlgorithmManager()
        algorithm = manager.get_algorithm("Szyfr Cezara")
        key = 7
        
        # Szyfrowanie
        encrypted_content = algorithm.encrypt(test_content, key)
        encrypted_file = test_file + '.encrypted'
        with open(encrypted_file, 'w', encoding='utf-8') as f:
            f.write(encrypted_content)
        print(f"✅ Zaszyfrowano plik: {encrypted_file}")
        
        # Deszyfrowanie
        decrypted_content = algorithm.decrypt(encrypted_content, key)
        decrypted_file = test_file + '.decrypted'
        with open(decrypted_file, 'w', encoding='utf-8') as f:
            f.write(decrypted_content)
        print(f"✅ Deszyfrowano plik: {decrypted_file}")
        
        # Sprawdź poprawność
        success = test_content == decrypted_content
        print(f"✅ Poprawność deszyfrowania: {success}")
        
        # Wyświetl zawartość
        print(f"\nOryginalny plik:")
        print(test_content)
        print(f"\nZaszyfrowany plik:")
        print(encrypted_content)
        print(f"\nDeszyfrowany plik:")
        print(decrypted_content)
        
    except Exception as e:
        print(f"❌ Błąd podczas testowania plików: {e}")
    
    finally:
        # Usuń pliki testowe
        for file in [test_file, encrypted_file, decrypted_file]:
            if os.path.exists(file):
                os.remove(file)
                print(f"🗑️ Usunięto plik: {file}")

if __name__ == "__main__":
    print("🔐 Test Aplikacji Kryptograficznej")
    print("=" * 50)
    
    test_caesar_cipher()
    test_algorithm_manager()
    test_file_operations()
    
    print("\n" + "=" * 50)
    print("✅ Wszystkie testy zakończone!")
    print("\nAby uruchomić aplikację GUI, użyj: python main.py")
