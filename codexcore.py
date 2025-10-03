"""
CodexCore - Advanced Cryptography Tool

Author: aegis
GitHub: https://github.com/MrSpy00
Version: 1.0
Python: 3.6+
"""

import base64
import binascii
import hashlib
import os
import secrets
import string
import time
from typing import Optional, Tuple
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass
import sys
import pyperclip

if sys.platform == 'win32':
    try:
        os.system('chcp 65001 >nul 2>&1')
        os.environ['PYTHONIOENCODING'] = 'utf-8'
    except Exception:
        pass

class CodexCore:
    """Advanced Cryptography Tool - Main Class"""
    
    MAX_FILE_SIZE = 100 * 1024 * 1024
    MAX_TEXT_LENGTH = 100000
    MAX_HASH_LENGTH = 1000000
    MAX_INPUT_LENGTH = 10000
    MIN_PASSWORD_LENGTH = 8
    MAX_PASSWORD_LENGTH = 128
    PBKDF2_ITERATIONS = 200000
    SALT_LENGTH = 32
    
    def __init__(self) -> None:
        """Initialize CodexCore"""
        self.version = "1.0"
        self.author = "aegis - GitHub: https://github.com/MrSpy00"
        self.language: Optional[str] = None
        self.clipboard_available = self.check_clipboard()
        
        self._sensitive_data: list[bytes | str] = []
        
        self.texts = {
            'tr': {
                'app_name': 'CodexCore',
                'app_desc': 'Gelişmiş Kriptografi Aracı',
                'version': 'Versiyon',
                'author': 'Yazar',
                'supported_methods': 'Desteklenen Yöntemler',
                'base64': 'Base64 Kodlama/Çözme',
                'aes': 'AES Şifreleme/Çözme',
                'rsa': 'RSA Şifreleme/Çözme',
                'hash': 'Hash Fonksiyonları (MD5, SHA-1, SHA-256, SHA-512)',
                'caesar': 'Caesar Şifresi',
                'vigenere': 'Vigenère Şifresi',
                'main_menu': 'ANA MENÜ',
                'exit': 'Çıkış',
                'back_to_main': 'Ana Menüye Dön',
                'select_language': 'Dil Seçimi',
                'turkish': 'Türkçe',
                'english': 'English',
                'choose_option': 'Seçiminiz',
                'invalid_choice': 'Geçersiz seçim!',
                'continue_enter': 'Devam etmek için Enter\'a basın...',
                'error': 'Hata',
                'success': 'Başarılı',
                'copy': 'Kopyala',
                'paste': 'Yapıştır',
                'encrypt': 'Şifrele',
                'decrypt': 'Çöz',
                'password': 'Şifre',
                'text': 'Metin',
                'file': 'Dosya',
                'path': 'Yol',
                'key': 'Anahtar',
                'shift': 'Kaydırma',
                'brute_force': 'Kaba Kuvvet',
                'generate_password': 'Şifre Üret',
                'file_encryption': 'Dosya Şifreleme',
                'hash_functions': 'Hash Fonksiyonları',
                'caesar_cipher': 'Caesar Şifresi',
                'vigenere_cipher': 'Vigenère Şifresi',
                'aes_operations': 'AES İşlemleri',
                'base64_operations': 'Base64 İşlemleri',
                'file_operations': 'Dosya İşlemleri',
                'password_generator': 'Şifre Üretici',
                'auto_key': 'Otomatik Anahtar',
                'with_password': 'Şifre ile',
                'all_shifts': 'Tüm Kaydırmaları Dene',
                'encrypt_file': 'Dosya Şifrele',
                'decrypt_file': 'Dosya Çöz',
                'enter_text': 'Metin girin',
                'enter_password': 'Şifre girin',
                'enter_key': 'Anahtar girin',
                'enter_shift': 'Kaydırma sayısı girin',
                'enter_file_path': 'Dosya yolu girin',
                'enter_encrypted_text': 'Şifrelenmiş metin girin',
                'enter_key_text': 'Anahtar metin girin',
                'enter_shift_number': 'Kaydırma sayısı (1-25)',
                'enter_file_path_encrypt': 'Şifrelenecek dosya yolu',
                'enter_file_path_decrypt': 'Çözülecek dosya yolu',
                'empty_input': 'Boş giriş!',
                'invalid_shift': 'Geçersiz kaydırma değeri!',
                'file_not_found': 'Dosya bulunamadı!',
                'password_too_short': 'Şifre çok kısa!',
                'operation_successful': 'İşlem başarılı!',
                'operation_failed': 'İşlem başarısız!',
                'copy_successful': 'Kopyalandı!',
                'copy_failed': 'Kopyalama başarısız!',
                'paste_successful': 'Yapıştırıldı!',
                'paste_failed': 'Yapıştırma başarısız!',
                'thank_you': 'Teşekkürler! Güvenli kalın! 🔒',
                'operation_cancelled': 'İşlem iptal edildi.',
                'unexpected_error': 'Beklenmeyen hata',
                'critical_error': 'Kritik hata',
                'program_closing': 'Program güvenli şekilde kapatılıyor...',
                'program_interrupted': 'Program kullanıcı tarafından sonlandırıldı.',
                'rsa_operations': 'RSA İşlemleri',
                'generate_key_pair': 'Anahtar Çifti Üret',
                'text_to_encrypt': 'Şifrelenecek metin',
                'encrypted_rsa_text': 'Çözülecek RSA metin',
                'key_pair_generated': 'Anahtar çifti oluşturuldu',
                'rsa_generating': 'RSA anahtar çifti üretiliyor...',
                'quick_password': 'Hızlı Şifre Üret (16 karakter)',
                'custom_password': 'Özelleştirilmiş Şifre Üret',
                'multiple_passwords': 'Çoklu Şifre Üret',
                'password_length': 'Şifre uzunluğu',
                'include_symbols': 'Semboller dahil olsun mu?',
                'include_numbers': 'Sayılar dahil olsun mu?',
                'include_uppercase': 'Büyük harfler dahil olsun mu?',
                'include_lowercase': 'Küçük harfler dahil olsun mu?',
                'how_many_passwords': 'Kaç şifre üretilsin?',
                'generated_password': 'Üretilen Şifre',
                'generated_passwords': 'Üretilen Şifreler',
                'hash_text': 'Hash\'lenecek metin',
                'all_hashes': 'Tüm Hash\'leri Hesapla',
                'all_hash_values': 'Tüm Hash Değerleri',
                'brute_force_text': 'Brute force yapılacak metin',
                'all_possible_shifts': 'Tüm olası kaydırmalar',
                'vigenere_key': 'Anahtar kelime',
                'encode_text': 'Şifrelenecek metin',
                'decode_text': 'Çözülecek Base64 metin',
                'text_to_decrypt': 'Çözülecek metin',
                'aes_key': 'AES Anahtarı',
                'encrypted_aes_text': 'Çözülecek AES metin',
                'file_to_encrypt': 'Şifrelenecek dosya yolu',
                'file_to_decrypt': 'Çözülecek dosya yolu',
                'clipboard_paste': 'Clipboard\'dan yapıştır',
                'manual_input': 'Manuel giriş için Enter\'a basın',
                'clipboard_path': 'Clipboard\'dan alınan yol',
                'clipboard_data_error': 'Clipboard\'dan veri alınamadı!',
                'shift_number': 'Kaydırma sayısı',
                'valid_number': 'Geçerli bir sayı girin!',
                'shift_range': 'Kaydırma sayısı 1-25 arasında olmalıdır!',
                'empty_text_error': 'Boş metin girişi!',
                'empty_key_error': 'Boş anahtar girişi!',
                'empty_password_error': 'Boş şifre girişi!',
                'copy_encrypted': 'Şifrelenmiş metni kopyala',
                'copy_key': 'Anahtarı kopyala',
                'continue_option': 'Devam et',
                'key_copied': 'Anahtar kopyalandı!',
                'copy_failed_error': 'Kopyalama başarısız!',
                'operation_interrupted': 'İşlem iptal edildi.',
                'unexpected_error_occurred': 'Beklenmeyen hata',
                'enter_number_0_8': 'Lütfen 0-8 arası bir sayı girin.',
                'warning': 'Uyarı',
                'input_too_long': 'Giriş çok uzun! Maksimum',
                'characters': 'karakter',
                'clipboard_too_long': 'Pano içeriği çok uzun! İlk',
                'characters_taken': 'karakter alındı',
                'starting_system': 'Sistem başlatılıyor',
                'loading_modules': 'Güvenlik modülleri yükleniyor',
                'base64_encoded': 'Base64 Kodlandı',
                'decoded_text': 'Çözülen Metin',
                'aes_encrypted': 'AES Şifrelendi',
                'aes_encrypted_password': 'AES Şifrelendi (Şifre)',
                'rsa_encrypted': 'RSA Şifrelendi',
                'decrypted_text': 'Çözülen Metin',
                'caesar_encrypted': 'Caesar Şifrelendi',
                'caesar_decrypted': 'Caesar Çözüldü',
                'vigenere_encrypted': 'Vigenère Şifrelendi',
                'vigenere_decrypted': 'Vigenère Çözüldü',
                'operations': 'İşlemleri',
                'key_must_contain_letter': 'Anahtar en az bir harf içermelidir!',
                'password_min_length': 'Şifre en az {min_length} karakter olmalıdır!',
                'encrypted_file_not_found': 'Şifrelenmiş dosya bulunamadı! Yol: {path}',
                'file_path_empty': 'Dosya yolu boş olamaz!',
                'invalid_file_path': 'Geçersiz dosya! Yol: {path}',
                'file_not_found': 'Dosya bulunamadı! Yol: {path}',
                'file_successfully_encrypted': 'Dosya başarıyla şifrelendi: {path}',
                'file_successfully_decrypted': 'Dosya başarıyla çözüldü: {path}',
                'text_too_long': 'Metin çok uzun! Maksimum {max_length} karakter desteklenir.',
                'file_too_large': 'Dosya çok büyük! Maksimum {max_size}MB desteklenir.',
                'encrypted_content_empty': 'Şifrelenmiş içerik boş!',
                'invalid_base64_data': 'Geçersiz Base64 verisi!',
                'invalid_encrypted_data': 'Geçersiz şifrelenmiş veri formatı!',
                'empty_text_encode': 'Boş metin kodlanamaz!',
                'invalid_characters': 'Geçersiz karakterler tespit edildi!',
                'empty_text_decode': 'Boş metin çözülemez!',
                'invalid_base64_format': 'Geçersiz Base64 formatı!',
                'empty_text_encrypt': 'Boş metin şifrelenemez!',
                'invalid_aes_key': 'Geçersiz AES anahtarı!',
                'empty_encrypted_text': 'Boş şifrelenmiş metin çözülemez!',
                'password_or_key_required': 'Şifre veya anahtar gerekli!',
                'empty_text_hash': 'Boş metin hash\'lenemez!'
            },
            'en': {
                'app_name': 'CodexCore',
                'app_desc': 'Advanced Cryptography Tool',
                'version': 'Version',
                'author': 'Author',
                'supported_methods': 'Supported Methods',
                'base64': 'Base64 Encoding/Decoding',
                'aes': 'AES Encryption/Decryption',
                'rsa': 'RSA Encryption/Decryption',
                'hash': 'Hash Functions (MD5, SHA-1, SHA-256, SHA-512)',
                'caesar': 'Caesar Cipher',
                'vigenere': 'Vigenère Cipher',
                'main_menu': 'MAIN MENU',
                'exit': 'Exit',
                'back_to_main': 'Back to Main Menu',
                'select_language': 'Language Selection',
                'turkish': 'Türkçe',
                'english': 'English',
                'choose_option': 'Your choice',
                'invalid_choice': 'Invalid choice!',
                'continue_enter': 'Press Enter to continue...',
                'error': 'Error',
                'success': 'Success',
                'copy': 'Copy',
                'paste': 'Paste',
                'encrypt': 'Encrypt',
                'decrypt': 'Decrypt',
                'password': 'Password',
                'text': 'Text',
                'file': 'File',
                'path': 'Path',
                'key': 'Key',
                'shift': 'Shift',
                'brute_force': 'Brute Force',
                'generate_password': 'Generate Password',
                'file_encryption': 'File Encryption',
                'hash_functions': 'Hash Functions',
                'caesar_cipher': 'Caesar Cipher',
                'vigenere_cipher': 'Vigenère Cipher',
                'aes_operations': 'AES Operations',
                'base64_operations': 'Base64 Operations',
                'file_operations': 'File Operations',
                'password_generator': 'Password Generator',
                'auto_key': 'Auto Key',
                'with_password': 'With Password',
                'all_shifts': 'Try All Shifts',
                'encrypt_file': 'Encrypt File',
                'decrypt_file': 'Decrypt File',
                'enter_text': 'Enter text',
                'enter_password': 'Enter password',
                'enter_key': 'Enter key',
                'enter_shift': 'Enter shift number',
                'enter_file_path': 'Enter file path',
                'enter_encrypted_text': 'Enter encrypted text',
                'enter_key_text': 'Enter key text',
                'enter_shift_number': 'Shift number (1-25)',
                'enter_file_path_encrypt': 'File path to encrypt',
                'enter_file_path_decrypt': 'File path to decrypt',
                'empty_input': 'Empty input!',
                'invalid_shift': 'Invalid shift value!',
                'file_not_found': 'File not found!',
                'password_too_short': 'Password too short!',
                'operation_successful': 'Operation successful!',
                'operation_failed': 'Operation failed!',
                'copy_successful': 'Copied!',
                'copy_failed': 'Copy failed!',
                'paste_successful': 'Pasted!',
                'paste_failed': 'Paste failed!',
                'thank_you': 'Thank you! Stay secure! 🔒',
                'operation_cancelled': 'Operation cancelled.',
                'unexpected_error': 'Unexpected error',
                'critical_error': 'Critical error',
                'program_closing': 'Program is closing safely...',
                'program_interrupted': 'Program interrupted by user.',
                'rsa_operations': 'RSA Operations',
                'generate_key_pair': 'Generate Key Pair',
                'text_to_encrypt': 'Text to encrypt',
                'encrypted_rsa_text': 'Encrypted RSA text to decrypt',
                'key_pair_generated': 'Key pair generated',
                'rsa_generating': 'Generating RSA key pair...',
                'quick_password': 'Quick Password Generate (16 characters)',
                'custom_password': 'Custom Password Generate',
                'multiple_passwords': 'Multiple Password Generate',
                'password_length': 'Password length',
                'include_symbols': 'Include symbols?',
                'include_numbers': 'Include numbers?',
                'include_uppercase': 'Include uppercase letters?',
                'include_lowercase': 'Include lowercase letters?',
                'how_many_passwords': 'How many passwords to generate?',
                'generated_password': 'Generated Password',
                'generated_passwords': 'Generated Passwords',
                'hash_text': 'Text to hash',
                'all_hashes': 'Calculate All Hashes',
                'all_hash_values': 'All Hash Values',
                'brute_force_text': 'Text for brute force',
                'all_possible_shifts': 'All possible shifts',
                'vigenere_key': 'Key word',
                'encode_text': 'Text to encode',
                'decode_text': 'Base64 text to decode',
                'text_to_decrypt': 'Text to decrypt',
                'aes_key': 'AES Key',
                'encrypted_aes_text': 'Encrypted AES text to decrypt',
                'file_to_encrypt': 'File path to encrypt',
                'file_to_decrypt': 'File path to decrypt',
                'clipboard_paste': 'Paste from clipboard',
                'manual_input': 'Press Enter for manual input',
                'clipboard_path': 'Path from clipboard',
                'clipboard_data_error': 'Could not get data from clipboard!',
                'shift_number': 'Shift number',
                'valid_number': 'Enter a valid number!',
                'shift_range': 'Shift number must be between 1-25!',
                'empty_text_error': 'Empty text input!',
                'empty_key_error': 'Empty key input!',
                'empty_password_error': 'Empty password input!',
                'copy_encrypted': 'Copy encrypted text',
                'copy_key': 'Copy key',
                'continue_option': 'Continue',
                'key_copied': 'Key copied!',
                'copy_failed_error': 'Copy failed!',
                'operation_interrupted': 'Operation interrupted.',
                'unexpected_error_occurred': 'Unexpected error occurred',
                'enter_number_0_8': 'Please enter a number between 0-8.',
                'warning': 'Warning',
                'input_too_long': 'Input too long! Maximum',
                'characters': 'characters',
                'clipboard_too_long': 'Clipboard content too long! First',
                'characters_taken': 'characters taken',
                'starting_system': 'Starting system',
                'loading_modules': 'Loading security modules',
                'base64_encoded': 'Base64 Encoded',
                'decoded_text': 'Decoded Text',
                'aes_encrypted': 'AES Encrypted',
                'aes_encrypted_password': 'AES Encrypted (Password)',
                'rsa_encrypted': 'RSA Encrypted',
                'decrypted_text': 'Decrypted Text',
                'caesar_encrypted': 'Caesar Encrypted',
                'caesar_decrypted': 'Caesar Decrypted',
                'vigenere_encrypted': 'Vigenère Encrypted',
                'vigenere_decrypted': 'Vigenère Decrypted',
                'operations': 'Operations',
                'key_must_contain_letter': 'Key must contain at least one letter!',
                'password_min_length': 'Password must be at least {min_length} characters!',
                'encrypted_file_not_found': 'Encrypted file not found! Path: {path}',
                'file_path_empty': 'File path cannot be empty!',
                'invalid_file_path': 'Invalid file! Path: {path}',
                'file_not_found': 'File not found! Path: {path}',
                'file_successfully_encrypted': 'File successfully encrypted: {path}',
                'file_successfully_decrypted': 'File successfully decrypted: {path}',
                'text_too_long': 'Text too long! Maximum {max_length} characters supported.',
                'file_too_large': 'File too large! Maximum {max_size}MB supported.',
                'encrypted_content_empty': 'Encrypted content is empty!',
                'invalid_base64_data': 'Invalid Base64 data!',
                'invalid_encrypted_data': 'Invalid encrypted data format!',
                'empty_text_encode': 'Empty text cannot be encoded!',
                'invalid_characters': 'Invalid characters detected!',
                'empty_text_decode': 'Empty text cannot be decoded!',
                'invalid_base64_format': 'Invalid Base64 format!',
                'empty_text_encrypt': 'Empty text cannot be encrypted!',
                'invalid_aes_key': 'Invalid AES key!',
                'empty_encrypted_text': 'Empty encrypted text cannot be decrypted!',
                'password_or_key_required': 'Password or key required!',
                'empty_text_hash': 'Empty text cannot be hashed!'
            }
        }
        
    def check_clipboard(self) -> bool:
        """Check clipboard support"""
        try:
            test_data = "test"
            pyperclip.copy(test_data)
            result = pyperclip.paste()
            del test_data
            return result == "test"
        except Exception:
            try:
                if sys.platform.startswith('linux'):
                    import subprocess
                    subprocess.run(['which', 'xclip'], check=True, capture_output=True)
                    return True
            except:
                pass
            return False
    
    def copy_to_clipboard(self, text: str) -> bool:
        """Copy text to clipboard"""
        if self.clipboard_available and text:
            try:
                pyperclip.copy(text)
                return True
            except Exception:
                return False
        return False
    
    def paste_from_clipboard(self) -> Optional[str]:
        """Paste text from clipboard"""
        if self.clipboard_available:
            try:
                result = pyperclip.paste()
                if result:
                    return result.strip()
                return None
            except Exception:
                return None
        return None
    
    def secure_cleanup(self) -> None:
        """Secure data cleanup"""
        try:
            for _ in self._sensitive_data:
                pass
            self._sensitive_data.clear()
        except Exception:
            pass
    
    def get_user_input(self, prompt: str, allow_paste: bool = True, max_length: Optional[int] = None) -> str:
        """Get user input"""
        if allow_paste and self.clipboard_available:
            self.print_colored(f"{prompt} (C: {self.get_text('paste')})", 'purple')
        else:
            self.print_colored(prompt, 'purple')
        
        user_input = input("> ").strip()
        
        if max_length is None:
            max_length = self.MAX_INPUT_LENGTH
        
        if len(user_input) > max_length:
            self.print_colored(f"{self.get_text('warning')}: {self.get_text('input_too_long')} {max_length} {self.get_text('characters')}.", 'yellow')
            user_input = user_input[:max_length]
        
        if allow_paste and self.clipboard_available and user_input.upper() == 'C':
            clipboard_text = self.paste_from_clipboard()
            if clipboard_text is not None:
                if len(clipboard_text) > max_length:
                    self.print_colored(f"{self.get_text('warning')}: {self.get_text('clipboard_too_long')} {max_length} {self.get_text('characters_taken')}.", 'yellow')
                    clipboard_text = clipboard_text[:max_length]
                
                self.print_colored(f"✓ {self.get_text('paste_successful')}: {clipboard_text[:50]}{'...' if len(clipboard_text) > 50 else ''}", 'green')
                return clipboard_text
            else:
                self.print_colored(f"✗ {self.get_text('paste_failed')}!", 'red')
                return ""
        
        return user_input
    
    def show_copy_option(self, result: str) -> None:
        """Show copy option"""
        if self.clipboard_available:
            self.print_colored(f"\nC: {self.get_text('copy')} | Enter: {self.get_text('continue_enter')}", 'purple')
            choice = input("> ").strip().upper()
            if choice == 'C':
                if self.copy_to_clipboard(result):
                    self.print_colored(f"✓ {self.get_text('copy_successful')}", 'green')
                else:
                    self.print_colored(f"✗ {self.get_text('copy_failed')}!", 'red')
    
    def clear_screen(self) -> None:
        """Clear screen"""
        try:
            if os.name == 'nt':
                os.system('cls')
            else:
                os.system('clear')
        except Exception:
            print('\n' * 50)
    
    def print_colored(self, text: str, color: str = 'white', end: str = '\n') -> None:
        """Print colored text"""
        try:
            colors = {
                'green': '\033[92m',
                'white': '\033[97m',
                'purple': '\033[95m',
                'yellow': '\033[93m',
                'red': '\033[91m',
                'cyan': '\033[96m',
                'reset': '\033[0m'
            }
            text = text.encode('utf-8', errors='replace').decode('utf-8')
            print(f"{colors.get(color, colors['white'])}{text}{colors['reset']}", end=end)
        except (UnicodeEncodeError, UnicodeDecodeError):
            try:
                print(text.encode('utf-8', errors='replace').decode('utf-8'), end=end)
            except:
                print(str(text), end=end)
    
    def animate_text(self, text: str, color: str = 'green', delay: float = 0.01) -> None:
        """Print animated text"""
        for char in text:
            self.print_colored(char, color, end='')
            time.sleep(delay)
        print()
    
    def show_loading(self, text: str, duration: float = 0.5) -> None:
        """Show loading animation"""
        chars = ['|', '/', '-', '\\']
        for i in range(int(duration * 10)):
            self.print_colored(f"\r{text} {chars[i % 4]}", 'purple')
            time.sleep(0.05)
        print()
    
    def language_selection(self) -> None:
        """Language selection"""
        while True:
            try:
                self.clear_screen()
                self.print_colored("================================================================", 'green')
                self.print_colored("                        CODEXCORE                              ", 'green')
                self.print_colored("                Gelişmiş Kriptografi Aracı                     ", 'white')
                self.print_colored("                Advanced Cryptography Tool                     ", 'white')
                self.print_colored("                                                                ", 'green')
                self.print_colored("    Version: 1.0 - Author: aegis - GitHub: https://github.com/MrSpy00", 'purple')
                self.print_colored("================================================================", 'green')
                print()
                
                self.print_colored("+-------------------------------------------------------------+", 'purple')
                self.print_colored("|                      DİL SEÇİMİ                            |", 'purple')
                self.print_colored("|                   LANGUAGE SELECTION                       |", 'purple')
                self.print_colored("+-------------------------------------------------------------+", 'purple')
                self.print_colored("|  1. Türkçe                                                 |", 'white')
                self.print_colored("|  2. English                                                |", 'white')
                self.print_colored("|  0. Çıkış / Exit                                          |", 'white')
                self.print_colored("+-------------------------------------------------------------+", 'purple')
                print()
                
                choice = input(f"{self.texts['tr']['choose_option']} (0-2): ").strip()
                
                if choice == '1':
                    self.language = 'tr'
                    break
                elif choice == '2':
                    self.language = 'en'
                    break
                elif choice == '0':
                    self.print_colored(f"\n{self.texts['tr']['exit']} yapılıyor...", 'yellow')
                    self.print_colored(f"{self.texts['tr']['thank_you']}", 'green')
                    sys.exit(0)
                else:
                    self.print_colored(f"{self.texts['tr']['invalid_choice']}", 'red')
                    input(f"{self.texts['tr']['continue_enter']}")
            except KeyboardInterrupt:
                self.print_colored(f"\n{self.texts['tr']['operation_cancelled']}", 'yellow')
                sys.exit(0)
            except Exception as e:
                self.print_colored(f"\n{self.texts['tr']['unexpected_error']}: {str(e)}", 'red')
                input(f"{self.texts['tr']['continue_enter']}")
    
    def get_text(self, key: str) -> str:
        """Get language text"""
        if self.language is None:
            return key
        return self.texts[self.language].get(key, key)
    
    def startup_animation(self) -> None:
        """Startup animation"""
        self.clear_screen()
        
        self.print_colored("================================================================", 'green')
        self.animate_text("                        CODEXCORE                              ", 'green', 0.01)
        self.animate_text("                Advanced Cryptography Tool                     ", 'white', 0.01)
        self.print_colored("================================================================", 'green')
        
        print()
        self.show_loading(self.get_text('starting_system'), 0.3)
        self.show_loading(self.get_text('loading_modules'), 0.3)
        
        time.sleep(0.2)
        self.clear_screen()
    
    def print_banner(self) -> None:
        """Print tool banner"""
        self.print_colored("================================================================", 'green')
        self.print_colored("                        CODEXCORE                              ", 'green')
        self.print_colored("                Gelişmiş Kriptografi Aracı                     ", 'white')
        self.print_colored("                Advanced Cryptography Tool                     ", 'white')
        self.print_colored("                                                                ", 'green')
        self.print_colored(f"    {self.get_text('version')}: 1.0 - {self.get_text('author')}: aegis - GitHub: https://github.com/MrSpy00", 'purple')
        self.print_colored("================================================================", 'green')
    
    def print_menu(self) -> None:
        """Print main menu"""
        self.print_colored("+-------------------------------------------------------------+", 'purple')
        self.print_colored(f"|                     {self.get_text('main_menu')}                          |", 'purple')
        self.print_colored("+-------------------------------------------------------------+", 'purple')
        self.print_colored(f"|  1. {self.get_text('base64_operations'):<50} |", 'white')
        self.print_colored(f"|  2. {self.get_text('aes_operations'):<50} |", 'white')
        self.print_colored(f"|  3. {self.get_text('rsa_operations'):<50} |", 'white')
        self.print_colored(f"|  4. {self.get_text('hash_functions'):<50} |", 'white')
        self.print_colored(f"|  5. {self.get_text('caesar_cipher'):<50} |", 'white')
        self.print_colored(f"|  6. {self.get_text('vigenere_cipher'):<50} |", 'white')
        self.print_colored(f"|  7. {self.get_text('password_generator'):<50} |", 'white')
        self.print_colored(f"|  8. {self.get_text('file_encryption'):<50} |", 'white')
        self.print_colored(f"|  0. {self.get_text('exit'):<50} |", 'white')
        self.print_colored("+-------------------------------------------------------------+", 'purple')
    
    def base64_encode(self, text: str) -> str:
        """Base64 encoding"""
        if not text:
            return f"{self.get_text('error')}: {self.get_text('empty_text_encode')}"
        
        try:
            text_bytes = text.encode('utf-8')
            encoded_bytes = base64.b64encode(text_bytes)
            return encoded_bytes.decode('ascii')
        except UnicodeEncodeError:
            return f"{self.get_text('error')}: {self.get_text('invalid_characters')}"
        except Exception as e:
            return f"{self.get_text('error')}: Base64 encoding failed - {str(e)}"
    
    def base64_decode(self, encoded_text: str) -> str:
        """Base64 decoding"""
        if not encoded_text:
            return f"{self.get_text('error')}: {self.get_text('empty_text_decode')}"
        
        valid_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
        if not all(c in valid_chars for c in encoded_text):
            return f"{self.get_text('error')}: {self.get_text('invalid_base64_format')}"
        
        try:
            missing_padding = len(encoded_text) % 4
            if missing_padding:
                encoded_text += '=' * (4 - missing_padding)
            
            decoded_bytes = base64.b64decode(encoded_text.encode('ascii'))
            return decoded_bytes.decode('utf-8')
        except (binascii.Error, UnicodeDecodeError):
            return f"{self.get_text('error')}: {self.get_text('invalid_base64_data')}"
        except Exception as e:
            return f"{self.get_text('error')}: Base64 decoding failed - {str(e)}"
    
    def base64_menu(self) -> None:
        """Base64 menu"""
        while True:
            try:
                self.print_colored("\n+-------------------------------------------------------------+", 'purple')
                self.print_colored(f"|                   {self.get_text('base64_operations').upper()}                         |", 'purple')
                self.print_colored("+-------------------------------------------------------------+", 'purple')
                self.print_colored(f"|  1. Encode ({self.get_text('encrypt')})                              |", 'white')
                self.print_colored(f"|  2. Decode ({self.get_text('decrypt')})                              |", 'white')
                self.print_colored(f"|  0. {self.get_text('back_to_main'):<50} |", 'white')
                self.print_colored("+-------------------------------------------------------------+", 'purple')
                
                choice = input(f"\n{self.get_text('choose_option')} (0-2): ").strip()
                
                if choice == '1':
                    text = self.get_user_input(f"\n{self.get_text('encode_text')}:")
                    if not text:
                        self.print_colored(f"{self.get_text('error')}: {self.get_text('empty_text_error')}", 'red')
                        input(f"\n{self.get_text('continue_enter')}")
                        continue
                    
                    result = self.base64_encode(text)
                    self.print_colored(f"\n{self.get_text('base64_encoded')}: {result}", 'green')
                    self.show_copy_option(result)
                    input(f"\n{self.get_text('continue_enter')}")
                    
                elif choice == '2':
                    encoded_text = self.get_user_input(f"\n{self.get_text('decode_text')}:")
                    if not encoded_text:
                        self.print_colored(f"{self.get_text('error')}: {self.get_text('empty_text_error')}", 'red')
                        input(f"\n{self.get_text('continue_enter')}")
                        continue
                    
                    result = self.base64_decode(encoded_text)
                    self.print_colored(f"\n{self.get_text('decoded_text')}: {result}", 'green')
                    self.show_copy_option(result)
                    input(f"\n{self.get_text('continue_enter')}")
                    
                elif choice == '0':
                    break
                else:
                    self.print_colored(f"{self.get_text('invalid_choice')} {self.get_text('valid_number')}", 'red')
                    input(f"\n{self.get_text('continue_enter')}")
            except KeyboardInterrupt:
                print(f"\n\n{self.get_text('operation_interrupted')}")
                break
            except Exception as e:
                print(f"\n{self.get_text('unexpected_error_occurred')}: {str(e)}")
                input(f"\n{self.get_text('continue_enter')}")
    
    def generate_aes_key(self, password: Optional[str] = None) -> Tuple[bytes, Optional[bytes]]:
        """Generate AES key"""
        try:
            if password:
                if len(password) < self.MIN_PASSWORD_LENGTH:
                    raise ValueError(self.get_text('password_min_length').format(min_length=self.MIN_PASSWORD_LENGTH))
                
                salt = os.urandom(self.SALT_LENGTH)
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA512(),
                    length=32,
                    salt=salt,
                    iterations=self.PBKDF2_ITERATIONS,
                )
                key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
                
                self._sensitive_data.extend([password, salt, key])
                
                return key, salt
            else:
                key = Fernet.generate_key()
                self._sensitive_data.append(key)
                return key, None
        except Exception as e:
            raise Exception(f"AES key generation failed: {str(e)}")
    
    def aes_encrypt(self, text: str, key: bytes, salt: Optional[bytes] = None) -> str:
        """AES encryption"""
        if not text:
            return f"{self.get_text('error')}: {self.get_text('empty_text_encrypt')}"
        
        try:
            if not key:
                return f"{self.get_text('error')}: {self.get_text('invalid_aes_key')}"
            
            f = Fernet(key)
            encrypted = f.encrypt(text.encode('utf-8'))
            
            if salt:
                combined = salt + encrypted
                return base64.urlsafe_b64encode(combined).decode('utf-8')
            else:
                return encrypted.decode('utf-8')
        except Exception as e:
            return f"{self.get_text('error')}: AES encryption failed - {str(e)}"
    
    def aes_decrypt(self, encrypted_text: str, password: Optional[str] = None, key: Optional[bytes] = None) -> str:
        """AES decryption"""
        if not encrypted_text:
            return f"{self.get_text('error')}: {self.get_text('empty_encrypted_text')}"
        
        try:
            if password:
                try:
                    encrypted_data = base64.urlsafe_b64decode(encrypted_text.encode('utf-8'))
                    if len(encrypted_data) < self.SALT_LENGTH:
                        return f"{self.get_text('error')}: {self.get_text('invalid_encrypted_data')}"
                    
                    salt = encrypted_data[:self.SALT_LENGTH]
                    encrypted_content = encrypted_data[self.SALT_LENGTH:]
                    
                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA512(),
                        length=32,
                        salt=salt,
                        iterations=self.PBKDF2_ITERATIONS,
                    )
                    derived_key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
                    
                    f = Fernet(derived_key)
                    decrypted = f.decrypt(encrypted_content)
                    return decrypted.decode('utf-8')
                except Exception as e:
                    return f"{self.get_text('error')}: AES decryption failed - {str(e)}"
            elif key:
                try:
                    f = Fernet(key)
                    encrypted = encrypted_text.encode('utf-8')
                    decrypted = f.decrypt(encrypted)
                    return decrypted.decode('utf-8')
                except Exception as e:
                    return f"{self.get_text('error')}: AES decryption failed - {str(e)}"
            else:
                return f"{self.get_text('error')}: {self.get_text('password_or_key_required')}"
                
        except Exception as e:
            return f"{self.get_text('error')}: AES decryption failed - {str(e)}"
    
    def aes_menu(self) -> None:
        """AES menu"""
        while True:
            try:
                self.print_colored("\n+-------------------------------------------------------------+", 'purple')
                self.print_colored(f"|                     {self.get_text('aes_operations').upper()}                          |", 'purple')
                self.print_colored("+-------------------------------------------------------------+", 'purple')
                self.print_colored(f"|  1. {self.get_text('encrypt')} ({self.get_text('auto_key')})                    |", 'white')
                self.print_colored(f"|  2. {self.get_text('decrypt')} ({self.get_text('auto_key')})                    |", 'white')
                self.print_colored(f"|  3. {self.get_text('encrypt')} ({self.get_text('with_password')})               |", 'white')
                self.print_colored(f"|  4. {self.get_text('decrypt')} ({self.get_text('with_password')})               |", 'white')
                self.print_colored(f"|  0. {self.get_text('back_to_main'):<50} |", 'white')
                self.print_colored("+-------------------------------------------------------------+", 'purple')
                
                choice = input(f"\n{self.get_text('choose_option')} (0-4): ").strip()
                
                if choice == '1':
                    text = self.get_user_input(f"\n{self.get_text('text_to_encrypt')}:")
                    if not text:
                        self.print_colored(f"{self.get_text('error')}: {self.get_text('empty_text_error')}", 'red')
                        input(f"\n{self.get_text('continue_enter')}")
                        continue
                    
                    try:
                        key, _ = self.generate_aes_key()
                        result = self.aes_encrypt(text, key)
                        self.print_colored(f"\n{self.get_text('aes_encrypted')}: {result}", 'green')
                        self.print_colored(f"{self.get_text('aes_key')}: {key.decode('utf-8')}", 'yellow')
                        
                        if self.clipboard_available:
                            self.print_colored(f"\nC: {self.get_text('copy_encrypted')} | K: {self.get_text('copy_key')} | Enter: {self.get_text('continue_option')}", 'purple')
                            copy_choice = input("> ").strip().upper()
                            if copy_choice == 'C':
                                if self.copy_to_clipboard(result):
                                    self.print_colored(f"✓ {self.get_text('copy_successful')}", 'green')
                                else:
                                    self.print_colored(f"✗ {self.get_text('copy_failed_error')}", 'red')
                            elif copy_choice == 'K':
                                if self.copy_to_clipboard(key.decode('utf-8')):
                                    self.print_colored(f"✓ {self.get_text('key_copied')}", 'green')
                                else:
                                    self.print_colored(f"✗ {self.get_text('copy_failed_error')}", 'red')
                    except Exception as e:
                        self.print_colored(f"{self.get_text('error')}: {str(e)}", 'red')
                    
                    input(f"\n{self.get_text('continue_enter')}")
                    
                elif choice == '2':
                    encrypted_text = self.get_user_input(f"\n{self.get_text('encrypted_aes_text')}:")
                    if not encrypted_text:
                        self.print_colored(f"{self.get_text('error')}: {self.get_text('empty_text_error')}", 'red')
                        input(f"\n{self.get_text('continue_enter')}")
                        continue
                    
                    key_text = self.get_user_input(f"\n{self.get_text('aes_key')}:")
                    if not key_text:
                        self.print_colored(f"{self.get_text('error')}: {self.get_text('empty_key_error')}", 'red')
                        input(f"\n{self.get_text('continue_enter')}")
                        continue
                    
                    try:
                        key = key_text.encode('utf-8')
                        result = self.aes_decrypt(encrypted_text, key=key)
                        self.print_colored(f"\n{self.get_text('decrypted_text')}: {result}", 'green')
                        self.show_copy_option(result)
                    except Exception as e:
                        self.print_colored(f"{self.get_text('error')}: {str(e)}", 'red')
                    
                    input(f"\n{self.get_text('continue_enter')}")
                    
                elif choice == '3':
                    text = self.get_user_input(f"\n{self.get_text('text_to_encrypt')}:")
                    if not text:
                        self.print_colored(f"{self.get_text('error')}: {self.get_text('empty_text_error')}", 'red')
                        input(f"\n{self.get_text('continue_enter')}")
                        continue
                    
                    password = getpass.getpass(f"{self.get_text('password')}: ")
                    if not password:
                        self.print_colored(f"{self.get_text('error')}: {self.get_text('empty_password_error')}", 'red')
                        input(f"\n{self.get_text('continue_enter')}")
                        continue
                    
                    try:
                        key, salt = self.generate_aes_key(password)
                        result = self.aes_encrypt(text, key, salt)
                        self.print_colored(f"\n{self.get_text('aes_encrypted_password')}: {result}", 'green')
                        self.show_copy_option(result)
                    except Exception as e:
                        self.print_colored(f"{self.get_text('error')}: {str(e)}", 'red')
                    
                    input(f"\n{self.get_text('continue_enter')}")
                    
                elif choice == '4':
                    encrypted_text = self.get_user_input(f"\n{self.get_text('encrypted_aes_text')}:")
                    if not encrypted_text:
                        self.print_colored(f"{self.get_text('error')}: {self.get_text('empty_text_error')}", 'red')
                        input(f"\n{self.get_text('continue_enter')}")
                        continue
                    
                    password = getpass.getpass(f"{self.get_text('password')}: ")
                    if not password:
                        self.print_colored(f"{self.get_text('error')}: {self.get_text('empty_password_error')}", 'red')
                        input(f"\n{self.get_text('continue_enter')}")
                        continue
                    
                    try:
                        result = self.aes_decrypt(encrypted_text, password=password)
                        self.print_colored(f"\n{self.get_text('decrypted_text')}: {result}", 'green')
                        self.show_copy_option(result)
                    except Exception as e:
                        self.print_colored(f"{self.get_text('error')}: {str(e)}", 'red')
                    
                    input(f"\n{self.get_text('continue_enter')}")
                    
                elif choice == '0':
                    break
                else:
                    self.print_colored(f"{self.get_text('invalid_choice')} {self.get_text('valid_number')}", 'red')
                    input(f"\n{self.get_text('continue_enter')}")
            except KeyboardInterrupt:
                print(f"\n\n{self.get_text('operation_interrupted')}")
                break
            except Exception as e:
                print(f"\n{self.get_text('unexpected_error_occurred')}: {str(e)}")
                input(f"\n{self.get_text('continue_enter')}")
    
    def generate_rsa_keys(self) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """Generate RSA key pair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    def rsa_encrypt(self, text: str, public_key: rsa.RSAPublicKey) -> str:
        """RSA encryption"""
        try:
            encrypted = public_key.encrypt(
                text.encode('utf-8'),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return base64.b64encode(encrypted).decode('utf-8')
        except Exception as e:
            return f"{self.get_text('error')}: {str(e)}"
    
    def rsa_decrypt(self, encrypted_text: str, private_key: rsa.RSAPrivateKey) -> str:
        """RSA decryption"""
        try:
            encrypted_data = base64.b64decode(encrypted_text.encode('utf-8'))
            decrypted = private_key.decrypt(
                encrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted.decode('utf-8')
        except Exception as e:
            return f"{self.get_text('error')}: {str(e)}"
    
    def rsa_menu(self) -> None:
        """RSA menu"""
        while True:
            self.print_colored("\n+-------------------------------------------------------------+", 'purple')
            self.print_colored(f"|                     {self.get_text('rsa_operations').upper()}                          |", 'purple')
            self.print_colored("+-------------------------------------------------------------+", 'purple')
            self.print_colored(f"|  1. {self.get_text('generate_key_pair'):<50} |", 'white')
            self.print_colored(f"|  2. {self.get_text('encrypt'):<50} |", 'white')
            self.print_colored(f"|  3. {self.get_text('decrypt'):<50} |", 'white')
            self.print_colored(f"|  0. {self.get_text('back_to_main'):<50} |", 'white')
            self.print_colored("+-------------------------------------------------------------+", 'purple')
            
            choice = input(f"\n{self.get_text('choose_option')} (0-3): ").strip()
            
            if choice == '1':
                print(f"\n{self.get_text('rsa_generating')}")
                private_key, public_key = self.generate_rsa_keys()
                
                private_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                
                public_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                
                with open('private_key.pem', 'wb') as f:
                    f.write(private_pem)
                with open('public_key.pem', 'wb') as f:
                    f.write(public_pem)
                
                print(f"✓ {self.get_text('key_pair_generated')}:")
                print("  - private_key.pem")
                print("  - public_key.pem")
                input(f"\n{self.get_text('continue_enter')}")
                
            elif choice == '2':
                text = self.get_user_input(f"\n{self.get_text('text_to_encrypt')}:")
                try:
                    with open('public_key.pem', 'rb') as f:
                        public_key = serialization.load_pem_public_key(f.read())
                    if isinstance(public_key, rsa.RSAPublicKey):
                        result = self.rsa_encrypt(text, public_key)
                    else:
                        result = f"{self.get_text('error')}: Invalid RSA public key!"
                    print(f"\n{self.get_text('rsa_encrypted')}: {result}")
                    
                    if self.clipboard_available and not result.startswith(f"{self.get_text('error')}:"):
                        self.show_copy_option(result)
                        
                except FileNotFoundError:
                    print(f"{self.get_text('error')}: public_key.pem file not found!")
                except Exception as e:
                    print(f"{self.get_text('error')}: {str(e)}")
                input(f"\n{self.get_text('continue_enter')}")
                
            elif choice == '3':
                encrypted_text = self.get_user_input(f"\n{self.get_text('encrypted_rsa_text')}:")
                try:
                    with open('private_key.pem', 'rb') as f:
                        private_key = serialization.load_pem_private_key(f.read(), password=None)
                    if isinstance(private_key, rsa.RSAPrivateKey):
                        result = self.rsa_decrypt(encrypted_text, private_key)
                    else:
                        result = f"{self.get_text('error')}: Invalid RSA private key!"
                    print(f"\n{self.get_text('decrypted_text')}: {result}")
                    
                    if self.clipboard_available and not result.startswith(f"{self.get_text('error')}:"):
                        self.show_copy_option(result)
                        
                except FileNotFoundError:
                    print(f"{self.get_text('error')}: private_key.pem file not found!")
                except Exception as e:
                    self.print_colored(f"{self.get_text('error')}: {str(e)}", 'red')
                input(f"\n{self.get_text('continue_enter')}")
                
            elif choice == '0':
                break
            else:
                self.print_colored(f"{self.get_text('invalid_choice')} {self.get_text('valid_number')}", 'red')
    
    def calculate_hash(self, text: str, algorithm: str) -> str:
        """Calculate hash"""
        if not text:
            return f"{self.get_text('error')}: {self.get_text('empty_text_hash')}"
        
        if len(text) > self.MAX_HASH_LENGTH:
            return f"{self.get_text('error')}: {self.get_text('text_too_long').format(max_length=self.MAX_HASH_LENGTH)}"
        
        supported_algorithms = ['md5', 'sha1', 'sha256', 'sha512']
        if algorithm not in supported_algorithms:
            return f"{self.get_text('error')}: Unsupported algorithm! Supported: {', '.join(supported_algorithms)}"
        
        try:
            text_bytes = text.encode('utf-8')
            
            algorithm_map = {
                'md5': hashlib.md5,
                'sha1': hashlib.sha1,
                'sha256': hashlib.sha256,
                'sha512': hashlib.sha512
            }
            
            hash_func = algorithm_map.get(algorithm)
            if not hash_func:
                return f"{self.get_text('error')}: Unsupported algorithm: {algorithm}"
            
            hash_obj = hash_func()
            hash_obj.update(text_bytes)
            return hash_obj.hexdigest()
        except UnicodeEncodeError:
            return f"{self.get_text('error')}: {self.get_text('invalid_characters')}"
        except MemoryError:
            return f"{self.get_text('error')}: Insufficient memory! Text too large."
        except Exception as e:
            return f"{self.get_text('error')}: Hash calculation failed - {str(e)}"
    
    def hash_menu(self) -> None:
        """Hash menu"""
        while True:
            self.print_colored("\n+-------------------------------------------------------------+", 'purple')
            self.print_colored(f"|                   {self.get_text('hash_functions').upper()}                           |", 'purple')
            self.print_colored("+-------------------------------------------------------------+", 'purple')
            self.print_colored("|  1. MD5 Hash                                              |", 'white')
            self.print_colored("|  2. SHA-1 Hash                                            |", 'white')
            self.print_colored("|  3. SHA-256 Hash                                          |", 'white')
            self.print_colored("|  4. SHA-512 Hash                                          |", 'white')
            self.print_colored(f"|  5. {self.get_text('all_hashes'):<50} |", 'white')
            self.print_colored(f"|  0. {self.get_text('back_to_main'):<50} |", 'white')
            self.print_colored("+-------------------------------------------------------------+", 'purple')
            
            choice = input(f"\n{self.get_text('choose_option')} (0-5): ").strip()
            
            if choice in ['1', '2', '3', '4', '5']:
                text = self.get_user_input(f"\n{self.get_text('hash_text')}:")
                
                if choice == '1':
                    result = self.calculate_hash(text, 'md5')
                    self.print_colored(f"\nMD5 Hash: {result}", 'green')
                    self.show_copy_option(result)
                elif choice == '2':
                    result = self.calculate_hash(text, 'sha1')
                    self.print_colored(f"\nSHA-1 Hash: {result}", 'green')
                    self.show_copy_option(result)
                elif choice == '3':
                    result = self.calculate_hash(text, 'sha256')
                    self.print_colored(f"\nSHA-256 Hash: {result}", 'green')
                    self.show_copy_option(result)
                elif choice == '4':
                    result = self.calculate_hash(text, 'sha512')
                    self.print_colored(f"\nSHA-512 Hash: {result}", 'green')
                    self.show_copy_option(result)
                elif choice == '5':
                    self.print_colored(f"\n{self.get_text('all_hash_values')}:", 'purple')
                    self.print_colored(f"MD5:     {self.calculate_hash(text, 'md5')}", 'white')
                    self.print_colored(f"SHA-1:   {self.calculate_hash(text, 'sha1')}", 'white')
                    self.print_colored(f"SHA-256: {self.calculate_hash(text, 'sha256')}", 'white')
                    self.print_colored(f"SHA-512: {self.calculate_hash(text, 'sha512')}", 'white')
                
                input(f"\n{self.get_text('continue_enter')}")
                
            elif choice == '0':
                break
            else:
                self.print_colored(f"{self.get_text('invalid_choice')} {self.get_text('valid_number')}", 'red')
    
    def caesar_cipher(self, text: str, shift: int, encrypt: bool = True) -> str:
        """Caesar cipher"""
        if not text:
            return f"{self.get_text('error')}: Empty text cannot be processed!"
        
        if len(text) > self.MAX_TEXT_LENGTH:
            return f"{self.get_text('error')}: {self.get_text('text_too_long').format(max_length=self.MAX_TEXT_LENGTH)}"
        
        if shift < 0 or shift > 25:
            return f"{self.get_text('error')}: Shift value must be between 0-25!"
        
        try:
            upper_offset = ord('A')
            lower_offset = ord('a')
            
            result: list[str] = []
            for char in text:
                if char.isalpha():
                    if char.isupper():
                        ascii_offset = upper_offset
                    else:
                        ascii_offset = lower_offset
                    
                    char_value = ord(char) - ascii_offset
                    if encrypt:
                        shifted_value = (char_value + shift) % 26
                    else:
                        shifted_value = (char_value - shift) % 26
                    
                    result.append(chr(shifted_value + ascii_offset))
                else:
                    result.append(char)
            return ''.join(result)
        except MemoryError:
            return f"{self.get_text('error')}: Insufficient memory! Text too large."
        except Exception as e:
            return f"{self.get_text('error')}: Caesar cipher operation failed - {str(e)}"
    
    def caesar_menu(self) -> None:
        """Caesar cipher menu"""
        while True:
            try:
                self.print_colored("\n+-------------------------------------------------------------+", 'purple')
                self.print_colored(f"|                {self.get_text('caesar_cipher').upper()} {self.get_text('operations').upper()}                     |", 'purple')
                self.print_colored("+-------------------------------------------------------------+", 'purple')
                self.print_colored(f"|  1. {self.get_text('encrypt'):<50} |", 'white')
                self.print_colored(f"|  2. {self.get_text('decrypt'):<50} |", 'white')
                self.print_colored(f"|  3. {self.get_text('brute_force')} ({self.get_text('all_shifts')})                   |", 'white')
                self.print_colored(f"|  0. {self.get_text('back_to_main'):<50} |", 'white')
                self.print_colored("+-------------------------------------------------------------+", 'purple')
                
                choice = input(f"\n{self.get_text('choose_option')} (0-3): ").strip()
                
                if choice == '1':
                    text = self.get_user_input(f"\n{self.get_text('text_to_encrypt')}:")
                    if not text:
                        self.print_colored(f"{self.get_text('error')}: {self.get_text('empty_text_error')}", 'red')
                        input(f"\n{self.get_text('continue_enter')}")
                        continue
                    
                    try:
                        shift = int(input(f"{self.get_text('shift_number')} (1-25): "))
                        if shift < 1 or shift > 25:
                            self.print_colored(f"{self.get_text('error')}: {self.get_text('shift_range')}", 'red')
                            input(f"\n{self.get_text('continue_enter')}")
                            continue
                    except ValueError:
                        self.print_colored(f"{self.get_text('error')}: {self.get_text('valid_number')}", 'red')
                        input(f"\n{self.get_text('continue_enter')}")
                        continue
                    
                    result = self.caesar_cipher(text, shift, True)
                    self.print_colored(f"\n{self.get_text('caesar_encrypted')}: {result}", 'green')
                    self.show_copy_option(result)
                    input(f"\n{self.get_text('continue_enter')}")
                    
                elif choice == '2':
                    text = self.get_user_input(f"\n{self.get_text('text_to_decrypt')}:")
                    if not text:
                        self.print_colored(f"{self.get_text('error')}: {self.get_text('empty_text_error')}", 'red')
                        input(f"\n{self.get_text('continue_enter')}")
                        continue
                    
                    try:
                        shift = int(input(f"{self.get_text('shift_number')} (1-25): "))
                        if shift < 1 or shift > 25:
                            self.print_colored(f"{self.get_text('error')}: {self.get_text('shift_range')}", 'red')
                            input(f"\n{self.get_text('continue_enter')}")
                            continue
                    except ValueError:
                        self.print_colored(f"{self.get_text('error')}: {self.get_text('valid_number')}", 'red')
                        input(f"\n{self.get_text('continue_enter')}")
                        continue
                    
                    result = self.caesar_cipher(text, shift, False)
                    self.print_colored(f"\n{self.get_text('caesar_decrypted')}: {result}", 'green')
                    self.show_copy_option(result)
                    input(f"\n{self.get_text('continue_enter')}")
                    
                elif choice == '3':
                    text = self.get_user_input(f"\n{self.get_text('brute_force_text')}:")
                    if not text:
                        self.print_colored(f"{self.get_text('error')}: {self.get_text('empty_text_error')}", 'red')
                        input(f"\n{self.get_text('continue_enter')}")
                        continue
                    
                    self.print_colored(f"\n{self.get_text('all_possible_shifts')}:", 'purple')
                    for shift in range(1, 26):
                        result = self.caesar_cipher(text, shift, False)
                        self.print_colored(f"Shift {shift:2d}: {result}", 'white')
                    input(f"\n{self.get_text('continue_enter')}")
                    
                elif choice == '0':
                    break
                else:
                    self.print_colored(f"{self.get_text('invalid_choice')} {self.get_text('valid_number')}", 'red')
                    input(f"\n{self.get_text('continue_enter')}")
            except KeyboardInterrupt:
                print(f"\n\n{self.get_text('operation_interrupted')}")
                break
            except Exception as e:
                print(f"\n{self.get_text('unexpected_error_occurred')}: {str(e)}")
                input(f"\n{self.get_text('continue_enter')}")
    
    def vigenere_cipher(self, text: str, key: str, encrypt: bool = True) -> str:
        """Vigenère cipher"""
        if not text:
            return f"{self.get_text('error')}: Empty text cannot be processed!"
        
        if not key:
            return f"{self.get_text('error')}: Key word cannot be empty!"
        
        if len(text) > self.MAX_TEXT_LENGTH:
            return f"{self.get_text('error')}: {self.get_text('text_too_long').format(max_length=self.MAX_TEXT_LENGTH)}"
        
        clean_key = ''.join(c.upper() for c in key if c.isalpha())
        if not clean_key:
            return f"{self.get_text('error')}: {self.get_text('key_must_contain_letter')}"
        
        try:
            key_values = [ord(c) - ord('A') for c in clean_key]
            key_length = len(key_values)
            
            result: list[str] = []
            key_index = 0
            
            for char in text:
                if char.isalpha():
                    if char.isupper():
                        ascii_offset = ord('A')
                    else:
                        ascii_offset = ord('a')
                    
                    key_char = key_values[key_index % key_length]
                    
                    char_value = ord(char) - ascii_offset
                    if encrypt:
                        shifted_value = (char_value + key_char) % 26
                    else:
                        shifted_value = (char_value - key_char) % 26
                    
                    result.append(chr(shifted_value + ascii_offset))
                    key_index += 1
                else:
                    result.append(char)
            return ''.join(result)
        except MemoryError:
            return f"{self.get_text('error')}: Insufficient memory! Text too large."
        except Exception as e:
            return f"{self.get_text('error')}: Vigenère cipher operation failed - {str(e)}"
    
    def vigenere_menu(self) -> None:
        """Vigenère cipher menu"""
        while True:
            self.print_colored("\n+-------------------------------------------------------------+", 'purple')
            self.print_colored(f"|               {self.get_text('vigenere_cipher').upper()} {self.get_text('operations').upper()}                    |", 'purple')
            self.print_colored("+-------------------------------------------------------------+", 'purple')
            self.print_colored(f"|  1. {self.get_text('encrypt'):<50} |", 'white')
            self.print_colored(f"|  2. {self.get_text('decrypt'):<50} |", 'white')
            self.print_colored(f"|  0. {self.get_text('back_to_main'):<50} |", 'white')
            self.print_colored("+-------------------------------------------------------------+", 'purple')
            
            choice = input(f"\n{self.get_text('choose_option')} (0-2): ").strip()
            
            if choice == '1':
                text = self.get_user_input(f"\n{self.get_text('text_to_encrypt')}:")
                key = self.get_user_input(f"{self.get_text('vigenere_key')}:")
                result = self.vigenere_cipher(text, key, True)
                self.print_colored(f"\n{self.get_text('vigenere_encrypted')}: {result}", 'green')
                self.show_copy_option(result)
                input(f"\n{self.get_text('continue_enter')}")
                
            elif choice == '2':
                text = self.get_user_input(f"\n{self.get_text('text_to_decrypt')}:")
                key = self.get_user_input(f"{self.get_text('vigenere_key')}:")
                result = self.vigenere_cipher(text, key, False)
                self.print_colored(f"\n{self.get_text('vigenere_decrypted')}: {result}", 'green')
                self.show_copy_option(result)
                input(f"\n{self.get_text('continue_enter')}")
                
            elif choice == '0':
                break
            else:
                self.print_colored(f"{self.get_text('invalid_choice')} {self.get_text('valid_number')}", 'red')
    
    def generate_password(self, length: int = 16, include_symbols: bool = True, include_numbers: bool = True, include_uppercase: bool = True, include_lowercase: bool = True) -> str:
        """Generate secure password"""
        try:
            if length < 4:
                return f"{self.get_text('error')}: Password length must be at least 4 characters!"
            if length > self.MAX_PASSWORD_LENGTH:
                return f"{self.get_text('error')}: Password length can be maximum {self.MAX_PASSWORD_LENGTH} characters!"
            
            chars = ""
            if include_lowercase:
                chars += string.ascii_lowercase
            if include_uppercase:
                chars += string.ascii_uppercase
            if include_numbers:
                chars += string.digits
            if include_symbols:
                chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
            
            if not chars:
                return f"{self.get_text('error')}: At least one character type must be selected!"
            
            password = ''.join(secrets.choice(chars) for _ in range(length))
            
            has_lower = any(c.islower() for c in password) if include_lowercase else True
            has_upper = any(c.isupper() for c in password) if include_uppercase else True
            has_digit = any(c.isdigit() for c in password) if include_numbers else True
            has_symbol = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password) if include_symbols else True
            
            max_attempts = 10
            attempt = 0
            while not (has_lower and has_upper and has_digit and has_symbol) and attempt < max_attempts:
                password = ''.join(secrets.choice(chars) for _ in range(length))
                has_lower = any(c.islower() for c in password) if include_lowercase else True
                has_upper = any(c.isupper() for c in password) if include_uppercase else True
                has_digit = any(c.isdigit() for c in password) if include_numbers else True
                has_symbol = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password) if include_symbols else True
                attempt += 1
            
            if attempt >= max_attempts:
                return f"{self.get_text('error')}: Could not generate password matching specified criteria!"
            
            return password
        except Exception as e:
            return f"{self.get_text('error')}: Password generation failed - {str(e)}"
    
    def password_generator_menu(self) -> None:
        """Password generator menu"""
        while True:
            self.print_colored("\n+-------------------------------------------------------------+", 'purple')
            self.print_colored(f"|                {self.get_text('password_generator').upper()}                       |", 'purple')
            self.print_colored("+-------------------------------------------------------------+", 'purple')
            self.print_colored(f"|  1. {self.get_text('quick_password'):<50} |", 'white')
            self.print_colored(f"|  2. {self.get_text('custom_password'):<50} |", 'white')
            self.print_colored(f"|  3. {self.get_text('multiple_passwords'):<50} |", 'white')
            self.print_colored(f"|  0. {self.get_text('back_to_main'):<50} |", 'white')
            self.print_colored("+-------------------------------------------------------------+", 'purple')
            
            choice = input(f"\n{self.get_text('choose_option')} (0-3): ").strip()
            
            if choice == '1':
                password = self.generate_password()
                self.print_colored(f"\n{self.get_text('generated_password')}: {password}", 'green')
                self.show_copy_option(password)
                input(f"\n{self.get_text('continue_enter')}")
                
            elif choice == '2':
                try:
                    length = int(input(f"{self.get_text('password_length')} (8-128): "))
                    include_symbols = input(f"{self.get_text('include_symbols')} (e/h): ").lower() == 'e'
                    include_numbers = input(f"{self.get_text('include_numbers')} (e/h): ").lower() == 'e'
                    include_uppercase = input(f"{self.get_text('include_uppercase')} (e/h): ").lower() == 'e'
                    include_lowercase = input(f"{self.get_text('include_lowercase')} (e/h): ").lower() == 'e'
                    
                    password = self.generate_password(length, include_symbols, include_numbers, include_uppercase, include_lowercase)
                    self.print_colored(f"\n{self.get_text('generated_password')}: {password}", 'green')
                    self.show_copy_option(password)
                except ValueError:
                    self.print_colored(f"{self.get_text('error')}: {self.get_text('valid_number')}", 'red')
                input(f"\n{self.get_text('continue_enter')}")
                
            elif choice == '3':
                try:
                    count = int(input(f"{self.get_text('how_many_passwords')} (1-20): "))
                    length = int(input(f"{self.get_text('password_length')} (8-128): "))
                    
                    self.print_colored(f"\n{self.get_text('generated_passwords')}:", 'purple')
                    for i in range(count):
                        password = self.generate_password(length)
                        self.print_colored(f"{i+1:2d}. {password}", 'white')
                except ValueError:
                    self.print_colored(f"{self.get_text('error')}: {self.get_text('valid_number')}", 'red')
                input(f"\n{self.get_text('continue_enter')}")
                
            elif choice == '0':
                break
            else:
                self.print_colored(f"{self.get_text('invalid_choice')} {self.get_text('valid_number')}", 'red')
    
    def encrypt_file(self, file_path: str, password: str) -> str:
        """File encryption"""
        file_path = file_path.strip().strip('"').strip("'")
        file_path = os.path.normpath(file_path)
        
        if not file_path:
            return f"{self.get_text('error')}: {self.get_text('file_path_empty')}"
        
        if not os.path.exists(file_path):
            return f"{self.get_text('error')}: {self.get_text('file_not_found').format(path=file_path)}"
        
        if not os.path.isfile(file_path):
            return f"{self.get_text('error')}: {self.get_text('invalid_file_path').format(path=file_path)}"
        
        if not password or len(password) < self.MIN_PASSWORD_LENGTH:
            return f"{self.get_text('error')}: {self.get_text('password_min_length').format(min_length=self.MIN_PASSWORD_LENGTH)}"
        
        try:
            file_size = os.path.getsize(file_path)
            if file_size > self.MAX_FILE_SIZE:
                return f"{self.get_text('error')}: {self.get_text('file_too_large').format(max_size=self.MAX_FILE_SIZE // (1024*1024))}"
            
            if file_size == 0:
                return f"{self.get_text('error')}: File is empty!"
            
            key, salt = self.generate_aes_key(password)
            
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            if not file_data:
                return f"{self.get_text('error')}: File could not be read!"
            
            f = Fernet(key)
            encrypted_data = f.encrypt(file_data)
            
            desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
            file_name = os.path.basename(file_path)
            base_name = os.path.splitext(file_name)[0]
            file_extension = os.path.splitext(file_name)[1]
            
            encrypted_file_path = os.path.join(desktop_path, f"{base_name}{file_extension}.encrypted")
            
            counter = 1
            while os.path.exists(encrypted_file_path):
                encrypted_file_path = os.path.join(desktop_path, f"{base_name}_{counter}{file_extension}.encrypted")
                counter += 1
            
            extension_info = file_extension.encode('utf-8')
            extension_length = len(extension_info).to_bytes(4, byteorder='big')
            
            with open(encrypted_file_path, 'wb') as f:
                if salt is not None:
                    f.write(salt + extension_length + extension_info + encrypted_data)
                else:
                    f.write(extension_length + extension_info + encrypted_data)
            
            del file_data, encrypted_data, key, salt
            
            return f"✓ {self.get_text('file_successfully_encrypted').format(path=encrypted_file_path)}"
        except PermissionError:
            return f"{self.get_text('error')}: No file write permission!"
        except OSError as e:
            return f"{self.get_text('error')}: File system error - {str(e)}"
        except Exception as e:
            return f"{self.get_text('error')}: File encryption failed - {str(e)}"
    
    def decrypt_file(self, encrypted_file_path: str, password: str) -> str:
        """File decryption"""
        encrypted_file_path = encrypted_file_path.strip().strip('"').strip("'")
        encrypted_file_path = os.path.normpath(encrypted_file_path)
        
        if not encrypted_file_path:
            return f"{self.get_text('error')}: {self.get_text('file_path_empty')}"
        
        if not os.path.exists(encrypted_file_path):
            return f"{self.get_text('error')}: {self.get_text('encrypted_file_not_found').format(path=encrypted_file_path)}"
        
        if not os.path.isfile(encrypted_file_path):
            return f"{self.get_text('error')}: {self.get_text('invalid_file_path').format(path=encrypted_file_path)}"
        
        if not password or len(password) < self.MIN_PASSWORD_LENGTH:
            return f"{self.get_text('error')}: {self.get_text('password_min_length').format(min_length=self.MIN_PASSWORD_LENGTH)}"
        
        try:
            with open(encrypted_file_path, 'rb') as f:
                encrypted_data = f.read()
            
            if len(encrypted_data) < self.SALT_LENGTH + 4:
                return f"{self.get_text('error')}: Invalid encrypted file format!"
            
            salt = encrypted_data[:self.SALT_LENGTH]
            
            extension_length = int.from_bytes(encrypted_data[self.SALT_LENGTH:self.SALT_LENGTH+4], byteorder='big')
            
            if len(encrypted_data) < self.SALT_LENGTH + 4 + extension_length:
                return f"{self.get_text('error')}: Invalid encrypted file format!"
            
            original_extension = encrypted_data[self.SALT_LENGTH+4:self.SALT_LENGTH+4+extension_length].decode('utf-8')
            
            encrypted_content = encrypted_data[self.SALT_LENGTH+4+extension_length:]
            
            if not encrypted_content:
                return f"{self.get_text('error')}: {self.get_text('encrypted_content_empty')}"
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA512(),
                length=32,
                salt=salt,
                iterations=self.PBKDF2_ITERATIONS,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
            
            f = Fernet(key)
            decrypted_data = f.decrypt(encrypted_content)
            
            desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
            file_name = os.path.basename(encrypted_file_path)
            base_name = os.path.splitext(file_name)[0]
            
            if base_name.endswith('.encrypted'):
                base_name = base_name[:-10]
            
            decrypted_file_path = os.path.join(desktop_path, f"{base_name}_decrypted{original_extension}")
            
            counter = 1
            while os.path.exists(decrypted_file_path):
                decrypted_file_path = os.path.join(desktop_path, f"{base_name}_decrypted_{counter}{original_extension}")
                counter += 1
            
            with open(decrypted_file_path, 'wb') as f:
                f.write(decrypted_data)
            
            del encrypted_data, encrypted_content, decrypted_data, key, salt
            
            return f"✓ {self.get_text('file_successfully_decrypted').format(path=decrypted_file_path)}"
        except PermissionError:
            return f"{self.get_text('error')}: No file write permission!"
        except OSError as e:
            return f"{self.get_text('error')}: File system error - {str(e)}"
        except Exception as e:
            return f"{self.get_text('error')}: File decryption failed - {str(e)}"
    
    def file_encryption_menu(self) -> None:
        """File encryption menu"""
        while True:
            self.print_colored("\n+-------------------------------------------------------------+", 'purple')
            self.print_colored(f"|               {self.get_text('file_encryption').upper()} {self.get_text('operations').upper()}                    |", 'purple')
            self.print_colored("+-------------------------------------------------------------+", 'purple')
            self.print_colored(f"|  1. {self.get_text('encrypt_file'):<50} |", 'white')
            self.print_colored(f"|  2. {self.get_text('decrypt_file'):<50} |", 'white')
            self.print_colored(f"|  0. {self.get_text('back_to_main'):<50} |", 'white')
            self.print_colored("+-------------------------------------------------------------+", 'purple')
            
            choice = input(f"\n{self.get_text('choose_option')} (0-2): ").strip()
            
            if choice == '1':
                self.print_colored(f"\n{self.get_text('file_to_encrypt')}:", 'purple')
                self.print_colored(f"C: {self.get_text('clipboard_paste')} | {self.get_text('manual_input')}", 'purple')
                file_input = input("> ").strip()
                
                if file_input.upper() == 'C':
                    file_path = self.paste_from_clipboard()
                    if file_path is None:
                        self.print_colored(f"{self.get_text('error')}: {self.get_text('clipboard_data_error')}", 'red')
                        input(f"\n{self.get_text('continue_enter')}")
                        continue
                    self.print_colored(f"{self.get_text('clipboard_path')}: {file_path}", 'green')
                else:
                    file_path = file_input
                
                password = getpass.getpass(f"{self.get_text('password')}: ")
                result = self.encrypt_file(file_path, password)
                self.print_colored(f"\n{result}", 'green' if result.startswith('✓') else 'red')
                input(f"\n{self.get_text('continue_enter')}")
                
            elif choice == '2':
                self.print_colored(f"\n{self.get_text('file_to_decrypt')}:", 'purple')
                self.print_colored(f"C: {self.get_text('clipboard_paste')} | {self.get_text('manual_input')}", 'purple')
                file_input = input("> ").strip()
                
                if file_input.upper() == 'C':
                    encrypted_file_path = self.paste_from_clipboard()
                    if encrypted_file_path is None:
                        self.print_colored(f"{self.get_text('error')}: {self.get_text('clipboard_data_error')}", 'red')
                        input(f"\n{self.get_text('continue_enter')}")
                        continue
                    self.print_colored(f"{self.get_text('clipboard_path')}: {encrypted_file_path}", 'green')
                else:
                    encrypted_file_path = file_input
                
                password = getpass.getpass(f"{self.get_text('password')}: ")
                result = self.decrypt_file(encrypted_file_path, password)
                self.print_colored(f"\n{result}", 'green' if result.startswith('✓') else 'red')
                input(f"\n{self.get_text('continue_enter')}")
                
            elif choice == '0':
                break
            else:
                self.print_colored(f"{self.get_text('invalid_choice')} {self.get_text('valid_number')}", 'red')
    
    def main(self) -> None:
        """Main program loop"""
        self.language_selection()
        
        self.startup_animation()
        
        while True:
            try:
                self.clear_screen()
                self.print_banner()
                self.print_menu()
                
                choice = input(f"\n{self.get_text('choose_option')} (0-8): ").strip()
                
                if choice == '1':
                    self.base64_menu()
                elif choice == '2':
                    self.aes_menu()
                elif choice == '3':
                    self.rsa_menu()
                elif choice == '4':
                    self.hash_menu()
                elif choice == '5':
                    self.caesar_menu()
                elif choice == '6':
                    self.vigenere_menu()
                elif choice == '7':
                    self.password_generator_menu()
                elif choice == '8':
                    self.file_encryption_menu()
                elif choice == '0':
                    self.print_colored(f"\n{self.get_text('exit')}...", 'yellow')
                    self.secure_cleanup()
                    self.print_colored(f"{self.get_text('thank_you')}", 'green')
                    break
                else:
                    self.print_colored(f"{self.get_text('invalid_choice')} {self.get_text('enter_number_0_8')}", 'red')
                    input(f"{self.get_text('continue_enter')}")
            except KeyboardInterrupt:
                self.print_colored(f"\n\n{self.get_text('program_interrupted')}", 'yellow')
                self.secure_cleanup()
                break
            except Exception as e:
                self.print_colored(f"\n{self.get_text('unexpected_error')}: {str(e)}", 'red')
                input(f"{self.get_text('continue_enter')}")

if __name__ == "__main__":
    tool = None
    try:
        tool = CodexCore()
        tool.main()
    except KeyboardInterrupt:
        print("\n\nProgram interrupted by user.")
        if tool:
            tool.secure_cleanup()
        sys.exit(0)
    except Exception as e:
        print(f"\nCritical error: {str(e)}")
        if tool:
            tool.secure_cleanup()
        print("Program is closing safely...")
        sys.exit(1)