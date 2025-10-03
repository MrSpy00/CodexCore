# 🔒 CodexCore - Gelişmiş Kriptografi Aracı
# Advanced Cryptography Tool

Bu araç, siber güvenlik uzmanları ve kriptografi meraklıları için geliştirilmiş kapsamlı bir şifreleme aracıdır. En yaygın kullanılan şifreleme yöntemlerini güvenli bir şekilde kullanmanızı sağlar.

## ✨ Özellikler

- **Gelişmiş Güvenlik**: PBKDF2-HMAC-SHA512 ile şifre türetme
- **Performans Optimizasyonu**: Daha hızlı işlem ve bellek yönetimi
- **Gelişmiş Hata Kontrolü**: Kapsamlı input validation ve edge case handling
- **Güvenli Bellek Yönetimi**: Hassas verilerin güvenli temizlenmesi
- **Kod Kalitesi**: Temiz ve optimize
- **Çoklu Dil Desteği**: Türkçe ve İngilizce arayüz


### 🔐 Şifreleme Yöntemleri
- **Base64 Encoding/Decoding** - Metin ve veri kodlama
- **AES Encryption/Decryption** - Gelişmiş şifreleme standardı
- **RSA Encryption/Decryption** - Asimetrik şifreleme
- **Caesar Cipher** - Klasik şifreleme yöntemi
- **Vigenère Cipher** - Çoklu alfabe şifreleme

### 🔍 Hash Fonksiyonları
- **MD5** - Hızlı hash hesaplama
- **SHA-1** - Güvenli hash algoritması
- **SHA-256** - Yüksek güvenlik hash
- **SHA-512** - En güçlü hash algoritması

### 🛠️ Ek Araçlar
- **Güvenli Şifre Üretici** - Kriptografik olarak güvenli şifreler
- **Dosya Şifreleme** - Dosyaları güvenli şekilde şifreleme
- **Brute Force Caesar** - Caesar cipher kırma aracı

## 🚀 Kurulum

### Gereksinimler
- Python 3.6 veya üzeri
- Gerekli kütüphaneler

### Kurulum Adımları

1. **Repository'yi klonlayın:**
```bash
git clone <[repository-url](https://github.com/MrSpy00/CodexCore)>
cd codexcore
```

2. **Gerekli paketleri yükleyin:**
```bash
pip install -r requirements.txt
```

3. **Aracı çalıştırın:**
```bash
python codexcore.py
```

## 📖 Kullanım

### Ana Menü
Program başlatıldığında aşağıdaki menü görüntülenir:

```
┌─────────────────────────────────────────────────────────────┐
│                        ANA MENÜ                             │
├─────────────────────────────────────────────────────────────┤
│  1. Base64 Encoding/Decoding                                │
│  2. AES Encryption/Decryption                               │
│  3. RSA Encryption/Decryption                               │
│  4. Hash Functions                                          │
│  5. Caesar Cipher                                           │
│  6. Vigenère Cipher                                         │
│  7. Güvenli Şifre Üretici                                   │
│  8. Dosya Şifreleme                                         │
│  0. Çıkış                                                   │
└─────────────────────────────────────────────────────────────┘
```

### Örnek Kullanımlar

#### Base64 Encoding
```
Seçiminiz: 1
1. Encode (Şifrele)
Şifrelenecek metin: Merhaba Dünya
Base64 Encoded: TWVyaGFiYSBEw7xueWE=
```

#### AES Şifreleme
```
Seçiminiz: 2
1. Şifrele (Otomatik Anahtar)
Şifrelenecek metin: Gizli mesaj
AES Encrypted: gAAAAABh...
AES Key: 8vK2...
```

#### Hash Hesaplama
```
Seçiminiz: 4
3. SHA-256 Hash
Hash'lenecek metin: test
SHA-256 Hash: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
```

## 🔧 Teknik Detaylar

### Güvenlik Özellikleri
- **Kriptografik Güvenlik**: Test edilmiş, hızlı ve güvenli
- **Salt Kullanımı**: PBKDF2-HMAC-SHA512 ile güvenli şifre türetme
- **Güvenli Hafıza**: Hassas verilerin güvenli temizlenmesi
- **Input Validation**: Kapsamlı giriş doğrulama ve sınır kontrolü
- **Hata Yönetimi**: Güvenli hata işleme ve loglama

### Desteklenen Algoritmalar
- **AES**: 256-bit anahtar, Fernet wrapper
- **RSA**: 2048-bit anahtar, OAEP padding
- **PBKDF2**: SHA-512 (geliştirilmiş güvenlik)
- **Hash**: MD5, SHA-1, SHA-256, SHA-512
- **Salt**: 256-bit (32 byte) güvenli salt üretimi

### Performans Özellikleri
- **Bellek Optimizasyonu**: Verimli bellek kullanımı
- **Hız Optimizasyonu**: Geliştirilmiş algoritma performansı
- **Dosya Boyutu Sınırları**: 100MB maksimum dosya boyutu
- **Metin Sınırları**: 100KB cipher, 1MB hash işlemleri

## ⚠️ Güvenlik Uyarıları

1. **Anahtar Güvenliği**: RSA ve AES anahtarlarınızı güvenli saklayın
2. **Şifre Gücü**: Güçlü şifreler kullanın (en az 12 karakter)
3. **Dosya Yedekleme**: Şifrelenmiş dosyaların yedeklerini alın
4. **Ağ Güvenliği**: Hassas verileri güvenli ağlarda kullanın

## 🐛 Hata Giderme

### Yaygın Sorunlar

**ImportError: No module named 'cryptography'**
```bash
pip install cryptography
```

**PermissionError: Dosya yazma hatası**
- Dosya izinlerini kontrol edin
- Yönetici olarak çalıştırın (gerekirse)

**UnicodeDecodeError: Karakter kodlama hatası**
- Dosya kodlamasını UTF-8 olarak kaydedin
- Özel karakterleri kontrol edin

## 📝 Lisans

Bu proje Apache License 2.0 altında lisanslanmıştır. Detaylar için LICENSE dosyasına bakın.



## 📞 İletişim

- **Geliştirici**: aegis
- **Versiyon**: 1.0
- **Telegram**: @hck6m
- **GitHub**: https://github.com/MrSpy00

## Not:

- **Yeni özellikler eklenecektir.**


---

**⚠️ Yasal Uyarı**: Bu araç sadece eğitim ve yasal amaçlar için tasarlanmıştır. Kötü niyetli kullanım sorumluluğu kullanıcıya aittir.

**🔒 Güvenlik**: Bu araç endüstri standardı güvenlik protokollerini kullanır, ancak mutlak güvenlik garantisi veremez. Kritik veriler için ek güvenlik önlemleri alın.



<div align="center">
<a href="https://buymeacoffee.com/aegissoft" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" height="45" width="170" alt="aegis" /></a></div>
