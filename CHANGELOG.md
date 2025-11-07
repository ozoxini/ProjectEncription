# Changelog

## [1.2.5a] - 07.11.2025

- **Szyfr RSA** - implemetnacja szyfru RSA, ktory szyfruje pliki, jak i tekst. Program generuje klucz publiczny i prywatny, umozliwiajac bezpiecznie szyforwanie.
- **Interfejs** - przeniesienie generowania kluczy do zakładki "pliki", oraz poprawiono UI.

## [1.2a] - 06.11.2025

- **Wielkosci klucza** - podczas szyfrowania tekstu/pliku, uzytkownik moze wybrac dlugosc klucza dla szyfru AES (we wszystkich trybach)

## [1.1.5a] - 04.11.2025

- **AES - CBC, CTR, GCM** - dodanie nowych trybów szyforwania
- **Poprawki UI** - wprowadzenie małych ulepszeń w interfejsie

## [1.1a] - 03.11.2025

- **Szyfr AES ECB** - "poprawna" implementacja szyfru AES w trybie ECB
- **Szyfr ChaCha20** = dodanie szyfru ChaCha20

## [1.0.5a] - 28.10.2025

- **Szyfr AES** - poprawienie działanie szyfru, (program nie zapisuje hasła, w celu deszyforwania nalezy podać poprawny klucz)

## [1.0.4a] - 27.10.2025

### Dodano

- **Szyfr AES** - implementacja uproszczonej wersji szyfru AES

## [1.0.3a] - 23.10.2025

- **Szyfr AES** - przygotwanie szkieletu algorytmu szyfrowania AES

## [1.0.2a] - 21.10.2025

### Dodano

- **Klucz biezący** - implementacja running key dla dwóch szyfrów: Vignere'a, oraz Beaufort'a

## [1.0.1a] - 20.10.2025

### Dodano

- **Szyfr Beaufort'a** - dodanie nowego szyfru
- **Szyfr Vignere'a** - dodanie nowego szyfru

## [1.0.0a] - 13.10.2025

### Dodano
- **Aplikacja GUI** - interfejs PyQt5
- **Szyfrowanie tekstu** - szyfrowanie i deszyfrowanie z poziomu aplikacji
- **Szyfrowanie plików** - mozliwość szyfrowania plików w ktorych znajduje się tekst
- **Szyfr Cezara** - implementacja z obsługą polskich znaków
- **Walidacja** - sprawdzanie kluczy i danych wejściowych
- **Menadzer szyfrów** - prosta funkcja ułatwiająca implementowanie nowych metod szyfrowania

## [0.1.0-preview] - 07.10.2025

### Dodano
- **Menu terminalowe** - podstawowy interfejs w konsoli
- **Szyfr Cezara** - implementacja klasycznego szyfru przesunięcia
- **Podstawowa funkcjonalność** - szyfrowanie tekstu