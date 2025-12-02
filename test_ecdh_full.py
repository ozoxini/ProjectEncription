#!/usr/bin/env python3
"""
Pełny test ECDH - Alice i Bob wymieniają wiadomości
"""

from src.crypto.ecdh_key_exchange import ECDHKeyExchange

print("=" * 70)
print("PEŁNY TEST ECDH - WYMIANA WIADOMOŚCI ALICE ↔ BOB")
print("=" * 70)

ecdh = ECDHKeyExchange()

# ============================================================================
# KROK 1: ALICE - Generuje parę
# ============================================================================
print("\n[ALICE] Krok 1: Generuję parę kluczy...")
alice_keys = ecdh.generate_keypair()
print(f"  ✓ Klucz publiczny Alice:")
print(f"    {alice_keys['public_key_b64'][:60]}...")
print(f"  ✓ Klucz prywatny Alice (HEX):")
print(f"    {alice_keys['private_key_hex'][:60]}...")

# ============================================================================
# KROK 2: BOB - Generuje parę
# ============================================================================
print("\n[BOB] Krok 2: Generuję parę kluczy...")
bob_keys = ecdh.generate_keypair()
print(f"  ✓ Klucz publiczny Bob:")
print(f"    {bob_keys['public_key_b64'][:60]}...")
print(f"  ✓ Klucz prywatny Bob (HEX):")
print(f"    {bob_keys['private_key_hex'][:60]}...")

# ============================================================================
# KROK 3: ALICE - Oblicza wspólny sekret
# ============================================================================
print("\n[ALICE] Krok 3: Obliczam wspólny sekret z kluczem publicznym Boba...")
alice_secret = ecdh.compute_shared_secret(
    alice_keys['private_key_int'],
    bob_keys['public_key_b64']
)
print(f"  ✓ Mój sekret (hex):")
print(f"    {alice_secret.hex()[:60]}...")

# ============================================================================
# KROK 4: BOB - Oblicza wspólny sekret
# ============================================================================
print("\n[BOB] Krok 4: Obliczam wspólny sekret z kluczem publicznym Alice...")
bob_secret = ecdh.compute_shared_secret(
    bob_keys['private_key_int'],
    alice_keys['public_key_b64']
)
print(f"  ✓ Mój sekret (hex):")
print(f"    {bob_secret.hex()[:60]}...")

# ============================================================================
# WERYFIKACJA - Sekrety muszą być identyczne!
# ============================================================================
print("\n" + "=" * 70)
print("WERYFIKACJA 1: Sekrety są identyczne?")
if alice_secret == bob_secret:
    print("✅ TAK! Sekrety są IDENTYCZNE!")
    print(f"    Wspólny sekret: {alice_secret.hex()}")
else:
    print("❌ NIE! Sekrety się nie zgadzają - BŁĄD!")
    exit(1)

# ============================================================================
# KROK 5: ALICE → BOB - Wysyła zaszyfrowaną wiadomość
# ============================================================================
print("\n[ALICE] Krok 5: Szyfruję wiadomość i wysyłam do Boba...")
message_1 = "Cześć Bob! Jak się masz? To jest moja pierwsza wiadomość."
print(f"  Oryginalna wiadomość: '{message_1}'")

encrypted_1 = ecdh.encrypt_message(message_1, alice_secret)
print(f"  ✓ Zaszyfrowana (Base64):")
print(f"    {encrypted_1[:60]}...")

# ============================================================================
# KROK 6: BOB - Deszyfruje wiadomość od Alice
# ============================================================================
print("\n[BOB] Krok 6: Deszyfruję wiadomość od Alice...")
try:
    decrypted_1 = ecdh.decrypt_message(encrypted_1, bob_secret)
    print(f"  ✓ Odszyfrowana wiadomość: '{decrypted_1}'")
except Exception as e:
    print(f"  ❌ Błąd deszyfrowania: {str(e)}")
    exit(1)

# ============================================================================
# WERYFIKACJA - Wiadomość się zgadza?
# ============================================================================
print("\n" + "=" * 70)
print("WERYFIKACJA 2: Wiadomość 1 (Alice → Bob) się zgadza?")
if message_1 == decrypted_1:
    print("✅ TAK! Wiadomość przeszła bez zmian!")
else:
    print("❌ NIE! Wiadomość się zmieniła!")
    exit(1)

# ============================================================================
# KROK 7: BOB → ALICE - Wysyła odpowiedź
# ============================================================================
print("\n[BOB] Krok 7: Szyfruję odpowiedź i wysyłam do Alice...")
message_2 = "Cześć Alice! Świetnie się mam! Twoja wiadomość dotarła bezpiecznie."
print(f"  Oryginalna wiadomość: '{message_2}'")

encrypted_2 = ecdh.encrypt_message(message_2, bob_secret)
print(f"  ✓ Zaszyfrowana (Base64):")
print(f"    {encrypted_2[:60]}...")

# ============================================================================
# KROK 8: ALICE - Deszyfruje odpowiedź od Boba
# ============================================================================
print("\n[ALICE] Krok 8: Deszyfruję odpowiedź od Boba...")
try:
    decrypted_2 = ecdh.decrypt_message(encrypted_2, alice_secret)
    print(f"  ✓ Odszyfrowana wiadomość: '{decrypted_2}'")
except Exception as e:
    print(f"  ❌ Błąd deszyfrowania: {str(e)}")
    exit(1)

# ============================================================================
# WERYFIKACJA - Wiadomość się zgadza?
# ============================================================================
print("\n" + "=" * 70)
print("WERYFIKACJA 3: Wiadomość 2 (Bob → Alice) się zgadza?")
if message_2 == decrypted_2:
    print("✅ TAK! Wiadomość przeszła bez zmian!")
else:
    print("❌ NIE! Wiadomość się zmieniła!")
    exit(1)

# ============================================================================
# KROK 9: Wymiana 3 - Wiadomość ze specjalnymi znakami
# ============================================================================
print("\n[ALICE] Krok 9: Szyfruję wiadomość ze specjalnymi znakami...")
message_3 = "Polskie znaki: ąćęłńóśźż, Emoji: 🔐 ✅, Liczby: 123456!"
print(f"  Oryginalna wiadomość: '{message_3}'")

encrypted_3 = ecdh.encrypt_message(message_3, alice_secret)
print(f"  ✓ Zaszyfrowana (Base64):")
print(f"    {encrypted_3[:60]}...")

print("\n[BOB] Krok 10: Deszyfruję wiadomość ze specjalnymi znakami...")
try:
    decrypted_3 = ecdh.decrypt_message(encrypted_3, bob_secret)
    print(f"  ✓ Odszyfrowana wiadomość: '{decrypted_3}'")
except Exception as e:
    print(f"  ❌ Błąd deszyfrowania: {str(e)}")
    exit(1)

# ============================================================================
# WERYFIKACJA - Wiadomość się zgadza?
# ============================================================================
print("\n" + "=" * 70)
print("WERYFIKACJA 4: Wiadomość 3 (ze specjalnymi znakami) się zgadza?")
if message_3 == decrypted_3:
    print("✅ TAK! Wiadomość ze specjalnymi znakami przeszła bez zmian!")
else:
    print("❌ NIE! Wiadomość się zmieniła!")
    exit(1)

# ============================================================================
# PODSUMOWANIE
# ============================================================================
print("\n" + "=" * 70)
print("🎉 WSZYSTKIE TESTY POWIODŁY SIĘ!")
print("=" * 70)
print("\n✅ Komunikacja Alice ↔ Bob działa prawidłowo!")
print("✅ ECDH generuje identyczne sekrety")
print("✅ Szyfrowanie/Deszyfrowanie jest niezawodne")
print("✅ Znaki specjalne, polskie znaki i emoji są obsługiwane")
print("\n" + "=" * 70)
