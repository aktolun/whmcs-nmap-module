<?php

declare(strict_types=1);

use WHMCS\Database\Capsule;
use WHMCS\Authentication\CurrentUser;

if (!defined("WHMCS")) {
    die("Bu dosyaya doğrudan erişim yasaktır.");
}

// Sınıfları manuel olarak yükle
require_once __DIR__ . '/lib/apiclient.php';

// Admin yetkisini kontrol eden fonksiyon
if (!function_exists('securityscanner_checkAdminPermission')) {
    function securityscanner_checkAdminPermission(): bool
    {
        $currentUser = new CurrentUser();
        
        // Kullanıcının admin yetkisi var mı kontrol et
        if (!$currentUser->isAuthenticatedAdmin()) {
            return false;
        }
        
        return true;
    }
}

// Modül yapılandırması
if (!function_exists('securityscanner_config')) {
    function securityscanner_config(): array
    {
        return [
            'name' => 'Security Scanner',
            'description' => 'Nmap tabanlı güvenlik tarama modülü',
            'version' => '1.0',
            'author' => 'Orçun Aktolun',
            'fields' => [
                'api_url' => [
                    'FriendlyName' => 'API URL',
                    'Type' => 'text',
                    'Size' => '50',
                    'Default' => 'http://localhost:3000',
                    'Description' => 'Nmap API sunucusunun URL adresi'
                ],
                'api_key' => [
                    'FriendlyName' => 'API Key',
                    'Type' => 'text',
                    'Size' => '50',
                    'Default' => '',
                    'Description' => 'Nmap API sunucusu için API anahtarı'
                ],
                'scan_interval' => [
                    'FriendlyName' => 'Tarama Aralığı',
                    'Type' => 'select',
                    'Options' => [
                        '3600' => 'Her Saat',
                        '86400' => 'Her Gün',
                        '604800' => 'Her Hafta',
                        '2592000' => 'Her Ay'
                    ],
                    'Default' => '86400',
                    'Description' => 'Otomatik taramaların ne sıklıkla yapılacağı'
                ],
                'scan_time' => [
                    'FriendlyName' => 'Tarama Saati',
                    'Type' => 'text',
                    'Size' => '5',
                    'Default' => '00:00',
                    'Description' => 'Günlük taramanın yapılacağı saat (HH:mm formatında)'
                ],
                'last_scan_time' => [
                    'FriendlyName' => 'Son Tarama Zamanı',
                    'Type' => 'text',
                    'Size' => '20',
                    'Default' => '',
                    'Description' => 'Son otomatik taramanın yapıldığı zaman'
                ]
            ]
        ];
    }
}

// Modül aktivasyon fonksiyonu
if (!function_exists('securityscanner_activate')) {
    function securityscanner_activate(): array
    {
        try {
            // Veritabanı tablolarını oluştur
            if (!Capsule::schema()->hasTable('mod_securityscanner_scans')) {
                Capsule::schema()->create('mod_securityscanner_scans', function ($table) {
                    $table->increments('id');
                    $table->string('target');
                    $table->string('status');
                    $table->text('results')->nullable();
                    $table->timestamp('started_at')->nullable();
                    $table->timestamp('completed_at')->nullable();
                    $table->timestamps();
                });
            }

            if (!Capsule::schema()->hasTable('mod_securityscanner_results')) {
                Capsule::schema()->create('mod_securityscanner_results', function ($table) {
                    $table->increments('id');
                    $table->string('ip_address');
                    $table->timestamp('scan_date');
                    $table->string('status');
                    $table->text('details')->nullable();
                    $table->timestamps();
                });
            }
            
            // Hook'ları kaydet
            add_hook('PreCronJob', 1, 'securityscanner_autoScan');
            
            return [
                'status' => 'success',
                'description' => 'Security Scanner modülü başarıyla etkinleştirildi.'
            ];
        } catch (\Exception $e) {
            return [
                'status' => 'error',
                'description' => 'Security Scanner modülü etkinleştirilemedi: ' . $e->getMessage()
            ];
        }
    }
}

// Modül deaktivasyon fonksiyonu
if (!function_exists('securityscanner_deactivate')) {
    function securityscanner_deactivate(): array
    {
        try {
            Capsule::schema()->dropIfExists('mod_securityscanner_scans');

            return [
                'status' => 'success',
                'description' => 'Security Scanner modülü başarıyla deaktif edildi.'
            ];
        } catch (\Exception $e) {
            return [
                'status' => 'error',
                'description' => 'Modül deaktif edilirken hata oluştu: ' . $e->getMessage()
            ];
        }
    }
}

// Modül çıktı fonksiyonu
if (!function_exists('securityscanner_output')) {
    function securityscanner_output($vars) {
        // Admin yetkisini kontrol et
        if (!securityscanner_checkAdminPermission()) {
            echo '<div class="alert alert-danger">
                <strong>Erişim Engellendi!</strong> Bu modülü kullanmak için yönetici yetkilerine sahip olmanız gerekmektedir.
            </div>';
            return;
        }
        
        $action = $_GET['action'] ?? '';

        // AJAX istekleri için header ayarları
        if ($action) {
            header('Content-Type: application/json');
            ob_clean(); // Önceki çıktı tamponunu temizle
        }

        switch ($action) {
            case 'startscan':
                handleStartScan($vars);
                break;
            case 'checkstatus':
                handleCheckStatus($vars);
                break;
            case 'getresults':
                handleGetResults($vars);
                break;
            case 'completedscans':
                handleCompletedScans($vars);
                break;
            case 'savesettings':
                handleSaveSettings($vars);
                break;
            default:
                displayMainPage($vars);
        }
    }
}

// Handler fonksiyonları
if (!function_exists('handleStartScan')) {
    function handleStartScan($vars): void
    {
        header('Content-Type: application/json');
        
        // Admin yetkisini kontrol et
        if (!securityscanner_checkAdminPermission()) {
            echo json_encode(['success' => false, 'error' => 'Erişim reddedildi: Yönetici yetkileri gerekli']);
            exit;
        }
        
        // POST verilerini al
        $ipAddress = $_POST['ip'] ?? $_POST['custom_ip'] ?? '';
        
        // Gelen verileri logla
        logActivity('Güvenlik Tarayıcı: Gelen tarama verileri - IP: ' . $ipAddress);
        
        if (empty($ipAddress)) {
            logActivity('Güvenlik Tarayıcı: IP adresi eksik');
            echo json_encode(['success' => false, 'error' => 'IP adresi gerekli']);
            return;
        }
        
        // IP adresini doğrula
        if (!filter_var($ipAddress, FILTER_VALIDATE_IP)) {
            logActivity('Güvenlik Tarayıcı: Geçersiz IP adresi formatı - ' . $ipAddress);
            echo json_encode(['success' => false, 'error' => 'Geçersiz IP adresi formatı']);
            return;
        }
        
        // IP adresini temizle
        $cleanIpAddress = preg_replace('/[^\d\.:a-fA-F]/', '', $ipAddress);
        
        // IP adresinin temizlendikten sonra hala geçerli olup olmadığını kontrol et
        if (!filter_var($cleanIpAddress, FILTER_VALIDATE_IP)) {
            logActivity('Güvenlik Tarayıcı: IP adresi temizlendikten sonra geçersiz hale geldi - ' . $ipAddress);
            echo json_encode(['success' => false, 'error' => 'IP adresi temizlendikten sonra geçersiz hale geldi']);
            return;
        }

        try {
            // API ayarlarını kontrol et
            if (empty($vars['api_url']) || empty($vars['api_key'])) {
                logActivity('Güvenlik Tarayıcı: API ayarları eksik');
                throw new \Exception('API ayarları eksik. Lütfen modül ayarlarını kontrol edin.');
            }

            // API URL'i kontrol et
            if (!filter_var($vars['api_url'], FILTER_VALIDATE_URL)) {
                logActivity('Güvenlik Tarayıcı: Geçersiz API URL formatı - ' . $vars['api_url']);
                throw new \Exception('Geçersiz API URL formatı.');
            }

            // API URL'den son slash'i kaldır
            $vars['api_url'] = rtrim($vars['api_url'], '/');

            $api = new Apiclient($vars);
            $result = $api->startScan($cleanIpAddress);
            
            if ($result['success']) {
                // Tarama durumunu kontrol et
                $statusResult = $api->getScanStatus($result['scan_id']);
                
                // Tarama başarıyla başlatıldıysa veritabanına kaydet
                Capsule::table('mod_securityscanner_results')->insert([
                    'ip_address' => $cleanIpAddress,
                    'scan_date' => date('Y-m-d H:i:s'),
                    'status' => $statusResult['success'] ? $statusResult['status'] : 'error',
                    'details' => json_encode([
                        'scan_id' => $result['scan_id'],
                        'message' => $statusResult['success'] ? $statusResult['message'] : 'Tarama durumu alınamadı'
                    ])
                ]);
                
                logActivity('Güvenlik Tarayıcı: IP ' . $cleanIpAddress . ' için tarama başlatıldı. Scan ID: ' . $result['scan_id']);
            }
            
            echo json_encode($result);
        } catch (\Exception $e) {
            logActivity('Güvenlik Tarayıcı: Tarama başlatma hatası - ' . $e->getMessage());
            echo json_encode(['success' => false, 'error' => $e->getMessage()]);
        }
        exit;
    }
}

if (!function_exists('handleCheckStatus')) {
    function handleCheckStatus($vars): void
    {
        header('Content-Type: application/json');
        
        // Admin yetkisini kontrol et
        if (!securityscanner_checkAdminPermission()) {
            echo json_encode(['success' => false, 'error' => 'Erişim reddedildi: Yönetici yetkileri gerekli']);
            exit;
        }
        
        $input = json_decode(file_get_contents('php://input'), true);
        $scanId = $input['scan_id'] ?? '';
        
        if (empty($scanId)) {
            echo json_encode(['success' => false, 'error' => 'Tarama ID gerekli']);
            return;
        }

        try {
            $api = new Apiclient($vars);
            $result = $api->getScanStatus($scanId);
            
            // Tarama durumunu veritabanında güncelle
            if ($result['success']) {
                Capsule::table('mod_securityscanner_results')
                    ->where('details->scan_id', $scanId)
                    ->update([
                        'status' => $result['status'],
                        'details' => json_encode([
                            'scan_id' => $scanId,
                            'message' => $result['message'] ?? 'Tarama durumu güncellendi'
                        ])
                    ]);
            }
            
            echo json_encode($result);
        } catch (\Exception $e) {
            echo json_encode(['success' => false, 'error' => $e->getMessage()]);
        }
        exit;
    }
}

if (!function_exists('handleGetResults')) {
    function handleGetResults($vars): void
    {
        header('Content-Type: application/json');
        
        // Admin yetkisini kontrol et
        if (!securityscanner_checkAdminPermission()) {
            echo json_encode(['success' => false, 'error' => 'Erişim reddedildi: Yönetici yetkileri gerekli']);
            exit;
        }
        
        // POST verilerini al
        $scanId = $_POST['scan_id'] ?? '';
        
        if (empty($scanId)) {
            echo json_encode(['success' => false, 'error' => 'Tarama ID gerekli']);
            return;
        }

        try {
            // Önce veritabanından detayları al
            $scan = Capsule::table('mod_securityscanner_results')
                ->where('id', $scanId)
                ->first();

            if (!$scan) {
                echo json_encode(['success' => false, 'error' => 'Tarama bulunamadı']);
                return;
            }

            $details = json_decode($scan->details, true);
            if (!isset($details['scan_id'])) {
                echo json_encode(['success' => false, 'error' => 'Tarama detayları bulunamadı']);
                return;
            }

            // API üzerinden sonuçları al
            $api = new Apiclient($vars);
            
            // Önce durumu kontrol et
            $statusResult = $api->getScanStatus($details['scan_id']);
            if (!$statusResult['success']) {
                echo json_encode([
                    'success' => false,
                    'error' => 'Tarama durumu alınamadı: ' . ($statusResult['error'] ?? 'Bilinmeyen hata')
                ]);
                return;
            }

            // Sonuçları al
            $result = $api->getScanResults($details['scan_id']);
            
            if ($result['success']) {
                // Sonuçları düzenli bir formatta göster
                $formattedResults = [
                    'ip_address' => $scan->ip_address,
                    'scan_date' => $scan->scan_date,
                    'status' => $statusResult['status'],
                    'scan_results' => $result['results']
                ];
                
                echo json_encode([
                    'success' => true,
                    'results' => json_encode($formattedResults, JSON_PRETTY_PRINT)
                ]);
            } else {
                echo json_encode([
                    'success' => false,
                    'error' => $result['error'] ?? 'Sonuçlar alınamadı'
                ]);
            }
        } catch (\Exception $e) {
            logActivity('Güvenlik Tarayıcı: Sonuç alma hatası - ' . $e->getMessage());
            echo json_encode([
                'success' => false,
                'error' => 'Sonuçlar alınırken bir hata oluştu: ' . $e->getMessage()
            ]);
        }
        exit;
    }
}

if (!function_exists('handleCompletedScans')) {
    function handleCompletedScans($vars): void
    {
        // Admin yetkisini kontrol et
        if (!securityscanner_checkAdminPermission()) {
            echo json_encode(['success' => false, 'error' => 'Erişim reddedildi: Yönetici yetkileri gerekli']);
            exit;
        }
        
        try {
            $api = new Apiclient($vars);
            $result = $api->getCompletedScans();
            echo json_encode($result);
        } catch (\Exception $e) {
            echo json_encode(['success' => false, 'error' => $e->getMessage()]);
        }
        exit;
    }
}

if (!function_exists('handleSaveSettings')) {
    function handleSaveSettings($vars): void
    {
        header('Content-Type: application/json');
        
        // Admin yetkisini kontrol et
        if (!securityscanner_checkAdminPermission()) {
            echo json_encode(['success' => false, 'error' => 'Erişim reddedildi: Yönetici yetkileri gerekli']);
            exit;
        }
        
        // POST verilerini al
        $scanInterval = $_POST['scan_interval'] ?? '';
        $scanTime = $_POST['scan_time'] ?? '';
        
        // Gelen verileri logla
        logActivity('Güvenlik Tarayıcı: Gelen ayar verileri - scan_interval: ' . $scanInterval . ', scan_time: ' . $scanTime);
        
        // Gelen verileri doğrula
        if (empty($scanInterval) || empty($scanTime)) {
            logActivity('Güvenlik Tarayıcı: Eksik parametreler - scan_interval: ' . $scanInterval . ', scan_time: ' . $scanTime);
            echo json_encode(['success' => false, 'error' => 'Eksik parametreler']);
            exit;
        }
        
        // Saat formatını kontrol et
        if (!preg_match('/^([01]?[0-9]|2[0-3]):[0-5][0-9]$/', $scanTime)) {
            logActivity('Güvenlik Tarayıcı: Geçersiz saat formatı - ' . $scanTime);
            echo json_encode(['success' => false, 'error' => 'Geçersiz saat formatı. HH:mm formatında olmalıdır.']);
            exit;
        }
        
        try {
            // Ayarları kaydet
            $settings = [
                'scan_interval' => $scanInterval,
                'scan_time' => $scanTime
            ];
            
            foreach ($settings as $setting => $value) {
                // Önce ayar var mı kontrol et
                $exists = Capsule::table('tbladdonmodules')
                    ->where('module', 'securityscanner')
                    ->where('setting', $setting)
                    ->exists();
                
                if ($exists) {
                    // Varsa güncelle
                    Capsule::table('tbladdonmodules')
                        ->where('module', 'securityscanner')
                        ->where('setting', $setting)
                        ->update(['value' => $value]);
                } else {
                    // Yoksa ekle
                    Capsule::table('tbladdonmodules')
                        ->insert([
                            'module' => 'securityscanner',
                            'setting' => $setting,
                            'value' => $value
                        ]);
                }
                
                logActivity('Güvenlik Tarayıcı: Ayar kaydedildi - ' . $setting . ' = ' . $value);
            }
            
            // Ayarları tekrar yükle
            $currentSettings = securityscanner_getSettings($vars);
            
            // Ayarları logla
            logActivity('Güvenlik Tarayıcı: Ayarlar güncellendi - ' . json_encode($currentSettings));
            
            echo json_encode([
                'success' => true,
                'settings' => $currentSettings
            ]);
        } catch (\Exception $e) {
            logActivity('Güvenlik Tarayıcı: Ayar kaydetme hatası - ' . $e->getMessage());
            echo json_encode(['success' => false, 'error' => $e->getMessage()]);
        }
        exit;
    }
}

if (!function_exists('displayMainPage')) {
    function displayMainPage($vars): void
    {
        // Admin yetkisini kontrol et
        if (!securityscanner_checkAdminPermission()) {
            echo '<div class="alert alert-danger">
                <strong>Erişim Engellendi!</strong> Bu modülü kullanmak için yönetici yetkilerine sahip olmanız gerekmektedir.
            </div>';
            return;
        }
        
        // WHMCS'den aktif hizmetlerin IP adreslerini al
        $query = Capsule::table('tblhosting')
            ->where('domainstatus', 'Active')
            ->whereNotNull('dedicatedip')
            ->where('dedicatedip', '!=', '')
            ->select(['id', 'dedicatedip'])
            ->get();

        $activeIps = [];
        foreach ($query as $hosting) {
            // IP adresini doğrula
            if (filter_var($hosting->dedicatedip, FILTER_VALIDATE_IP)) {
                // IP adresini temizle
                $cleanIpAddress = preg_replace('/[^\d\.:a-fA-F]/', '', $hosting->dedicatedip);
                
                // Temizlendikten sonra hala geçerli mi kontrol et
                if (filter_var($cleanIpAddress, FILTER_VALIDATE_IP)) {
                    $activeIps[] = [
                        'id' => $hosting->id,
                        'ip' => $cleanIpAddress
                    ];
                }
            }
        }

        // Tamamlanan taramaları veritabanından al
        $completedScans = Capsule::table('mod_securityscanner_results')
            ->orderBy('scan_date', 'desc')
            ->get()
            ->map(function($scan) use ($vars) {
                // Uzak sunucudan güncel durumu al
                try {
                    $api = new Apiclient($vars);
                    $details = json_decode($scan->details, true);
                    if (isset($details['scan_id'])) {
                        $statusResult = $api->getScanStatus($details['scan_id']);
                        if ($statusResult['success']) {
                            // Veritabanını güncelle
                            Capsule::table('mod_securityscanner_results')
                                ->where('id', $scan->id)
                                ->update([
                                    'status' => $statusResult['status'],
                                    'details' => json_encode([
                                        'scan_id' => $details['scan_id'],
                                        'message' => $statusResult['message'] ?? 'Tarama durumu güncellendi'
                                    ])
                                ]);
                            
                            return [
                                'id' => $scan->id,
                                'ip_address' => $scan->ip_address,
                                'scan_date' => $scan->scan_date,
                                'status' => $statusResult['status'],
                                'details' => json_encode([
                                    'scan_id' => $details['scan_id'],
                                    'message' => $statusResult['message'] ?? 'Tarama durumu güncellendi'
                                ])
                            ];
                        }
                    }
                } catch (\Exception $e) {
                    logActivity('Güvenlik Tarayıcı: Durum güncelleme hatası - ' . $e->getMessage());
                }
                
                // Hata durumunda mevcut veriyi döndür
                return [
                    'id' => $scan->id,
                    'ip_address' => $scan->ip_address,
                    'scan_date' => $scan->scan_date,
                    'status' => $scan->status,
                    'details' => $scan->details
                ];
            })
            ->toArray();

        // Modül ayarlarını al
        $settings = securityscanner_getSettings($vars);
        
        // Template dosyasının yolunu belirle
        $templateFile = __DIR__ . '/templates/overview.tpl';
        
        // Template dosyası var mı kontrol et
        if (!file_exists($templateFile)) {
            logActivity('Security Scanner: Template dosyası bulunamadı: ' . $templateFile);
            die('Template dosyası bulunamadı');
        }
        
        // Smarty template engine'i başlat
        $smarty = new WHMCS\Smarty();
        
        // Template değişkenlerini ata
        $smarty->assign('activeIps', $activeIps);
        $smarty->assign('completedScans', $completedScans);
        $smarty->assign('settings', $settings);
        $smarty->assign('modulelink', 'addonmodules.php?module=securityscanner');
        $smarty->assign('error', '');
        $smarty->assign('scanStatus', null);
        $smarty->assign('scanResults', null);
        
        // Template'i yükle ve göster
        echo $smarty->fetch($templateFile);
    }
}

// Tarama başlatma fonksiyonu
if (!function_exists('startScan')) {
    function startScan($ipAddress, $vars = null): array
    {
        // Bu fonksiyon genellikle iç işlemler için kullanıldığından ve 
        // otomatik taramalar tarafından çağrıldığından, burada admin kontrolü
        // yapmamak daha uygun olabilir. Ancak doğrudan API çağrıları için önlem olarak
        // eklemek istiyorsanız, şu şekilde uygulayabilirsiniz:
        
        // Eğer doğrudan web isteği ise (özellikle API çağrısı)
        if (isset($_SERVER['REQUEST_METHOD']) && !defined('CRONJOB')) {
            $currentUser = new CurrentUser();
            if (!$currentUser->isAuthenticatedAdmin()) {
                return [
                    'success' => false, 
                    'error' => 'Erişim reddedildi: Yönetici yetkileri gerekli'
                ];
            }
        }
        
        // IP adresini doğrula
        if (!filter_var($ipAddress, FILTER_VALIDATE_IP)) {
            logActivity('Güvenlik Tarayıcı: Geçersiz IP adresi formatı - ' . $ipAddress);
            return ['success' => false, 'error' => 'Geçersiz IP adresi formatı'];
        }
        
        // IP adresini temizle
        $ipAddress = preg_replace('/[^\d\.:a-fA-F]/', '', $ipAddress);
        
        // IP adresinin temizlendikten sonra hala geçerli olup olmadığını kontrol et
        if (!filter_var($ipAddress, FILTER_VALIDATE_IP)) {
            logActivity('Güvenlik Tarayıcı: IP adresi temizlendikten sonra geçersiz hale geldi - ' . $ipAddress);
            return ['success' => false, 'error' => 'IP adresi temizlendikten sonra geçersiz hale geldi'];
        }
        
        try {
            $api = new Apiclient($vars);
            return $api->startScan($ipAddress);
        } catch (\Exception $e) {
            logActivity('Güvenlik Tarayıcı: IP ' . $ipAddress . ' için tarama başlatılamadı: ' . $e->getMessage());
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }
}

// Otomatik tarama için zamanlanmış görev
if (!function_exists('securityscanner_autoScan')) {
    function securityscanner_autoScan($vars): void
    {
        try {
            logActivity('Güvenlik Tarayıcı: Otomatik tarama kontrolü başlatıldı - ' . date('Y-m-d H:i:s'));
            
            // Ayarları veritabanından al
            $scanInterval = Capsule::table('tbladdonmodules')
                ->where('module', 'securityscanner')
                ->where('setting', 'scan_interval')
                ->value('value') ?? 86400;
                
            $scanTime = Capsule::table('tbladdonmodules')
                ->where('module', 'securityscanner')
                ->where('setting', 'scan_time')
                ->value('value') ?? '00:00';
                
            $lastScanTime = Capsule::table('tbladdonmodules')
                ->where('module', 'securityscanner')
                ->where('setting', 'last_scan_time')
                ->value('value') ?? '';

            logActivity('Güvenlik Tarayıcı: Ayarlar - Aralık: ' . $scanInterval . ', Saat: ' . $scanTime . ', Son Tarama: ' . $lastScanTime);

            // Tarama saatini kontrol et
            $currentHour = (int)date('H');
            $currentMinute = (int)date('i');
            list($targetHour, $targetMinute) = explode(':', $scanTime);
            
            logActivity('Güvenlik Tarayıcı: Saat kontrolü - Şu an: ' . $currentHour . ':' . $currentMinute . ', Hedef: ' . $targetHour . ':' . $targetMinute);
            
            // Saatlik tarama için dakika kontrolü
            if ($scanInterval === 3600) {
                // Hedef dakikaya ulaşıldı mı kontrol et (1 dakika tolerans)
                if (abs($currentMinute - (int)$targetMinute) > 1) {
                    logActivity('Güvenlik Tarayıcı: Saatlik tarama için dakika kontrolü başarısız.');
                    return;
                }
                logActivity('Güvenlik Tarayıcı: Saatlik tarama için dakika kontrolü başarılı.');
            } else {
                // Saat ve dakika kontrolü (1 dakika tolerans)
                if (abs($currentHour - (int)$targetHour) > 0 || abs($currentMinute - (int)$targetMinute) > 1) {
                    logActivity('Güvenlik Tarayıcı: Tarama saati henüz gelmedi.');
                    return;
                }
            }

            // Son tarama zamanını kontrol et
            if (!empty($lastScanTime)) {
                $lastScanTimestamp = strtotime($lastScanTime);
                $currentTime = time();
                $timeDiff = $currentTime - $lastScanTimestamp;
                
                logActivity('Güvenlik Tarayıcı: Zaman kontrolü - Son taramadan bu yana geçen süre: ' . $timeDiff . ' saniye');
                
                // Eğer son taramadan bu yana yeterli süre geçmediyse çık
                if ($timeDiff < $scanInterval) {
                    logActivity('Güvenlik Tarayıcı: Tarama aralığı henüz dolmadı. Son tarama: ' . $lastScanTime);
                    return;
                }
            }

            // Aktif IP'leri al
            $activeIps = Capsule::table('tblhosting')
                ->where('domainstatus', 'Active')
                ->whereNotNull('dedicatedip')
                ->where('dedicatedip', '!=', '')
                ->select('dedicatedip')
                ->get()
                ->map(function ($item) {
                    // IP adresini doğrula
                    if (!empty($item->dedicatedip) && filter_var($item->dedicatedip, FILTER_VALIDATE_IP)) {
                        // IP adresini temizle
                        $cleanIpAddress = preg_replace('/[^\d\.:a-fA-F]/', '', $item->dedicatedip);
                        
                        // Temizlendikten sonra hala geçerli mi kontrol et
                        if (filter_var($cleanIpAddress, FILTER_VALIDATE_IP)) {
                            return [
                                'dedicatedip' => $cleanIpAddress
                            ];
                        }
                    }
                    return null;
                })
                ->filter() // null değerleri filtrele
                ->toArray();

            if (empty($activeIps)) {
                logActivity('Güvenlik Tarayıcı: Tarama yapılacak aktif IP bulunamadı.');
                return;
            }

            logActivity('Güvenlik Tarayıcı: Otomatik tarama başlatılıyor. IP sayısı: ' . count($activeIps));

            // Her IP için tarama başlat
            foreach ($activeIps as $ip) {
                if (!empty($ip['dedicatedip'])) {
                    // IP adresini doğrula
                    if (!filter_var($ip['dedicatedip'], FILTER_VALIDATE_IP)) {
                        logActivity('Güvenlik Tarayıcı: Geçersiz IP adresi formatı - ' . $ip['dedicatedip']);
                        continue; // Bu IP'yi atla ve diğerine geç
                    }
                    
                    // IP adresini temizle
                    $cleanIpAddress = preg_replace('/[^\d\.:a-fA-F]/', '', $ip['dedicatedip']);
                    
                    // IP adresinin temizlendikten sonra hala geçerli olup olmadığını kontrol et
                    if (!filter_var($cleanIpAddress, FILTER_VALIDATE_IP)) {
                        logActivity('Güvenlik Tarayıcı: IP adresi temizlendikten sonra geçersiz hale geldi - ' . $ip['dedicatedip']);
                        continue; // Bu IP'yi atla ve diğerine geç
                    }
                    
                    logActivity('Güvenlik Tarayıcı: IP taraması başlatılıyor - ' . $cleanIpAddress);
                    
                    // API üzerinden taramayı başlat
                    $api = new Apiclient($vars);
                    $result = $api->startScan($cleanIpAddress);
                    
                    if ($result['success']) {
                        // Tarama durumunu kontrol et
                        $statusResult = $api->getScanStatus($result['scan_id']);
                        
                        // Tarama başarıyla başlatıldıysa veritabanına kaydet
                        Capsule::table('mod_securityscanner_results')->insert([
                            'ip_address' => $cleanIpAddress,
                            'scan_date' => date('Y-m-d H:i:s'),
                            'status' => $statusResult['success'] ? $statusResult['status'] : 'error',
                            'details' => json_encode([
                                'scan_id' => $result['scan_id'],
                                'message' => $statusResult['success'] ? $statusResult['message'] : 'Tarama durumu alınamadı'
                            ])
                        ]);
                        
                        logActivity('Güvenlik Tarayıcı: IP ' . $cleanIpAddress . ' için tarama başlatıldı. Scan ID: ' . $result['scan_id'] . ', Durum: ' . ($statusResult['success'] ? $statusResult['status'] : 'error'));
                    } else {
                        logActivity('Güvenlik Tarayıcı: IP ' . $cleanIpAddress . ' için tarama başlatılamadı - ' . ($result['error'] ?? 'Bilinmeyen hata'));
                    }
                }
            }

            // Son tarama zamanını güncelle
            $exists = Capsule::table('tbladdonmodules')
                ->where('module', 'securityscanner')
                ->where('setting', 'last_scan_time')
                ->exists();
                
            if ($exists) {
                Capsule::table('tbladdonmodules')
                    ->where('module', 'securityscanner')
                    ->where('setting', 'last_scan_time')
                    ->update(['value' => date('Y-m-d H:i:s')]);
            } else {
                Capsule::table('tbladdonmodules')
                    ->insert([
                        'module' => 'securityscanner',
                        'setting' => 'last_scan_time',
                        'value' => date('Y-m-d H:i:s')
                    ]);
            }

            logActivity('Güvenlik Tarayıcı: Otomatik tarama tamamlandı.');

        } catch (\Exception $e) {
            logActivity('Güvenlik Tarayıcı Otomatik Tarama Hatası: ' . $e->getMessage());
        }
    }
}

// Modül ayarlarını getir
if (!function_exists('securityscanner_getSettings')) {
    function securityscanner_getSettings($vars) {
        try {
            // Veritabanından ayarları al
            $settings = Capsule::table('tbladdonmodules')
                ->where('module', 'securityscanner')
                ->whereIn('setting', ['scan_interval', 'scan_time', 'last_scan_time'])
                ->get()
                ->pluck('value', 'setting')
                ->toArray();

            // Varsayılan değerleri ayarla
            $defaultSettings = [
                'scan_interval' => '86400',
                'scan_time' => '00:00',
                'last_scan_time' => ''
            ];

            // Veritabanından gelen değerleri varsayılan değerlerle birleştir
            $mergedSettings = array_merge($defaultSettings, $settings);

            // Boş değerleri kontrol et ve varsayılan değerlerle doldur
            foreach ($mergedSettings as $key => $value) {
                if (empty($value)) {
                    $mergedSettings[$key] = $defaultSettings[$key];
                }
            }

            // Ayarları logla
            logActivity('Güvenlik Tarayıcı: Ayarlar veritabanından yüklendi - ' . json_encode($mergedSettings));

            // Ayarları $vars'a ekle
            $vars['scan_interval'] = $mergedSettings['scan_interval'];
            $vars['scan_time'] = $mergedSettings['scan_time'];
            $vars['last_scan_time'] = $mergedSettings['last_scan_time'];

            return $mergedSettings;
        } catch (Exception $e) {
            logActivity('Security Scanner: Ayarları getirme hatası: ' . $e->getMessage());
            return [
                'scan_interval' => '86400',
                'scan_time' => '00:00',
                'last_scan_time' => ''
            ];
        }
    }
}

/**
 * Taramayı başlatan fonksiyon
 * @param array $vars Hook parametreleri
 * @return array Sonuç bilgisi
 */
if (!function_exists('securityscanner_startScan')) {
    function securityscanner_startScan($vars)
    {
        // Eğer doğrudan web isteği ise admin kontrolü yap
        if (isset($_SERVER['REQUEST_METHOD']) && !defined('CRONJOB')) {
            $currentUser = new CurrentUser();
            if (!$currentUser->isAuthenticatedAdmin()) {
                return [
                    'success' => false, 
                    'error' => 'Erişim reddedildi: Yönetici yetkileri gerekli'
                ];
            }
        }
        
        try {
            // Aktif IP'leri al
            $activeIps = Capsule::table('tblhosting')
                ->where('domainstatus', 'Active')
                ->select('dedicatedip')
                ->get()
                ->map(function ($item) {
                    // IP adresini doğrula
                    if (!empty($item->dedicatedip) && filter_var($item->dedicatedip, FILTER_VALIDATE_IP)) {
                        // IP adresini temizle
                        $cleanIpAddress = preg_replace('/[^\d\.:a-fA-F]/', '', $item->dedicatedip);
                        
                        // Temizlendikten sonra hala geçerli mi kontrol et
                        if (filter_var($cleanIpAddress, FILTER_VALIDATE_IP)) {
                            return [
                                'dedicatedip' => $cleanIpAddress
                            ];
                        }
                    }
                    return null;
                })
                ->filter() // null değerleri filtrele
                ->toArray();

            if (empty($activeIps)) {
                return [
                    'success' => false,
                    'error' => 'Aktif IP bulunamadı'
                ];
            }

            // Her IP için tarama başlat
            foreach ($activeIps as $ip) {
                if (!empty($ip['dedicatedip'])) {
                    // IP adresini doğrula
                    if (!filter_var($ip['dedicatedip'], FILTER_VALIDATE_IP)) {
                        logActivity('Güvenlik Tarayıcı: Geçersiz IP adresi formatı - ' . $ip['dedicatedip']);
                        continue; // Bu IP'yi atla ve diğerine geç
                    }
                    
                    // IP adresini temizle
                    $cleanIpAddress = preg_replace('/[^\d\.:a-fA-F]/', '', $ip['dedicatedip']);
                    
                    // IP adresinin temizlendikten sonra hala geçerli olup olmadığını kontrol et
                    if (!filter_var($cleanIpAddress, FILTER_VALIDATE_IP)) {
                        logActivity('Güvenlik Tarayıcı: IP adresi temizlendikten sonra geçersiz hale geldi - ' . $ip['dedicatedip']);
                        continue; // Bu IP'yi atla ve diğerine geç
                    }
                    
                    logActivity('Güvenlik Tarayıcı: IP taraması başlatılıyor - ' . $cleanIpAddress);
                    
                    // API üzerinden taramayı başlat
                    $api = new Apiclient($vars);
                    $result = $api->startScan($cleanIpAddress);
                    
                    if ($result['success']) {
                        // Tarama durumunu kontrol et
                        $statusResult = $api->getScanStatus($result['scan_id']);
                        
                        // Tarama başarıyla başlatıldıysa veritabanına kaydet
                        Capsule::table('mod_securityscanner_results')->insert([
                            'ip_address' => $cleanIpAddress,
                            'scan_date' => date('Y-m-d H:i:s'),
                            'status' => $statusResult['success'] ? $statusResult['status'] : 'error',
                            'details' => json_encode([
                                'scan_id' => $result['scan_id'],
                                'message' => $statusResult['success'] ? $statusResult['message'] : 'Tarama durumu alınamadı'
                            ])
                        ]);
                        
                        logActivity('Güvenlik Tarayıcı: IP ' . $cleanIpAddress . ' için tarama başlatıldı. Scan ID: ' . $result['scan_id'] . ', Durum: ' . ($statusResult['success'] ? $statusResult['status'] : 'error'));
                    } else {
                        logActivity('Güvenlik Tarayıcı: IP ' . $cleanIpAddress . ' için tarama başlatılamadı - ' . ($result['error'] ?? 'Bilinmeyen hata'));
                    }
                }
            }

            return [
                'success' => true,
                'message' => 'Tüm IP\'ler için tarama başlatıldı'
            ];
        } catch (\Exception $e) {
            logActivity('Güvenlik Tarayıcı: Tarama hatası - ' . $e->getMessage());
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }
}