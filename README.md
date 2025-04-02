# WHMCS NMap Modülü 

Bu modül **TRNOG Topluluğu** için geliştirilmiştir. Bu modül ile müşterileriniz tarafından aktif kullanımda olan IP adresleri üzerinde nmap taraması gerçekleştirebilir ve sonuçları WHMCS üzerinde görüntüleyebilirsiniz. Ayrıca dilerseniz WHMCS'de kayıtlı olmayan IP adresleri üzerinde de tarama işlemi gerçekleştirebilirsiniz.


## Gereksinimler

- WHMCS 8.0 ve üzeri
- PHP 7.4 veya daha yeni
- Curl PHP eklentisi
- JSON PHP eklentisi
- Nmap API sunucusu (ayrı olarak kurulmalıdır)

## Kurulum

### 1. Modül Dosyalarını Yükleme

Modül dosyalarını WHMCS'in kök dizinindeki uygun klasörlere yükleyin:

```bash
# GitHub'dan projeyi indirin
git clone https://github.com/aktolun/whmcs-nmap-module.git

# Dosyaları WHMCS dizinine kopyalayın
cp -r whmcs-nmap-module/modules/addons/securityscanner /path/to/whmcs/modules/addons/
```

Burada `/path/to/whmcs/` kısmını WHMCS'nizin kurulu olduğu gerçek dizin yolu ile değiştirin.

### 2. Modülü Etkinleştirme

1. WHMCS admin panelinize giriş yapın
2. **Sistem Ayarları** > **Eklenti Modülleri** menüsüne gidin
3. "Security Scanner" modülünü bulun ve **Etkinleştir** butonuna tıklayın

### 3. API Sunucusu Kurulumu

Modülün çalışması için Nmap API sunucusuna ihtiyaç vardır. Bu sunucu ayrı bir makinede veya aynı sunucuda çalışabilir.

#### PM2 ile API Sunucusu Kurulumu:

1. Node.js ve npm'i kurun (eğer kurulu değilse):
   ```bash
   curl -fsSL https://deb.nodesource.com/setup_16.x | sudo -E bash -
   sudo apt-get install -y nodejs
   ```

2. PM2'yi global olarak yükleyin:
   ```bash
   npm install pm2 -g
   ```

3. API sunucusu projesini GitHub'dan indirin:
   ```bash
   git clone https://github.com/aktolun/whmcs-nmap-module.git
   cd whmcs-nmap-module
   ```

4. Bağımlılıkları yükleyin:
   ```bash
   npm install
   ```

5. Yapılandırma dosyasını düzenleyin:
   ```bash
   cp .env.example .env
   nano .env
   ```
   
   `.env` dosyasında şu ayarları yapın:
   ```
   PORT=3000
   API_KEY=sizin_api_anahtarınız
   LOG_LEVEL=info
   ```

6. PM2 ile API sunucusunu başlatın:
   ```bash
   pm2 start server.js --name "whmcs-nmap-module"
   ```

7. PM2'yi sistem açılışında otomatik başlatmak için:
   ```bash
   pm2 startup
   pm2 save
   ```

8. Sunucunun çalıştığını doğrulayın:
   ```bash
   pm2 status
   curl http://localhost:3000/status -H "Authorization: Bearer sizin_api_anahtarınız"
   ```

9. API sunucusu loglarını görüntülemek için:
   ```bash
   pm2 logs whmcs-nmap-module
   ```

10. Sunucuyu yeniden başlatmak için:
    ```bash
    pm2 restart whmcs-nmap-module
    ```

Bu adımları tamamladıktan sonra, WHMCS Security Scanner modülünün ayarlarında "API URL" alanına `http://localhost:3000` (veya sunucunuzun IP adresini) ve "API Key" alanına oluşturduğunuz API anahtarını girin.

Not: Güvenlik için, API anahtarınızı karmaşık ve tahmin edilemez yapın ve API sunucunuza dış erişimleri güvenlik duvarı ile sınırlayın.

#### Standart Yöntem ile API Sunucusu Kurulumu:

1. Node.js ve npm'i kurun (eğer kurulu değilse):
   ```bash
   curl -fsSL https://deb.nodesource.com/setup_16.x | sudo -E bash -
   sudo apt-get install -y nodejs
   ```

2. API sunucusu projesini GitHub'dan indirin:
   ```bash
   git clone https://github.com/aktolun/whmcs-nmap-module.git
   cd whmcs-nmap-module
   ```

3. Bağımlılıkları yükleyin:
   ```bash
   npm install
   ```

4. Yapılandırma dosyasını düzenleyin:
   ```bash
   cp .env.example .env
   nano .env
   ```
   
   `.env` dosyasında şu ayarları yapın:
   ```
   PORT=3000
   API_KEY=sizin_api_anahtarınız
   LOG_LEVEL=info
   ```

5. API sunucusunu başlatın:
   ```bash
   node server.js
   ```

6. API sunucusu varsayılan olarak 3000 portunda çalışacaktır

### 4. Modül Ayarları

1. WHMCS admin panelinde **Eklentiler** > **Security Scanner** menüsüne gidin
2. Aşağıdaki bilgileri doldurun:
   - **API URL**: Nmap API sunucusunun URL'si (örn: http://localhost:3000)
   - **API Key**: API sunucusu için oluşturduğunuz API anahtarı
   - **Tarama Aralığı**: Otomatik taramaların yapılacağı sıklık
   - **Tarama Saati**: Günlük taramaların yapılacağı saat

## Kullanım

### Manuel Tarama

1. WHMCS admin panelinde **Eklentiler** > **Security Scanner** menüsüne gidin
2. "Aktif IP'lerden Tarama" bölümünden bir IP seçin veya "Özel IP Tarama" bölümünden bir IP adresi girin
3. "Taramayı Başlat" butonuna tıklayın
4. Tarama sonuçları tamamlandığında, sonuçları görüntülemek için "Detayları Görüntüle" butonuna tıklayın

### Otomatik Tarama

1. "Tarama Aralığı" ve "Tarama Saati" ayarlarını yapılandırın
2. WHMCS cron işi çalıştığında, belirtilen zamanda otomatik taramalar gerçekleştirilecektir
3. Tarama sonuçları "Tamamlanan Taramalar" bölümünde listelenecektir

## Hata Ayıklama

Modül hakkında detaylı bilgileri WHMCS sistem loglarında bulabilirsiniz. Log kayıtları şu başlık altında listelenir: "Güvenlik Tarayıcı: "

Sık karşılaşılan hatalar:

1. **API sunucusuna bağlanılamıyor**: API URL'nin doğru olduğundan ve API sunucusunun çalıştığından emin olun
2. **API anahtarı hatası**: API anahtarınızın doğru olduğunu kontrol edin
3. **Tarama başlatılamıyor**: IP adresinin geçerli olduğundan emin olun
4. **Sonuçlar görüntülenemiyor**: Taramanın tamamlandığından emin olun

