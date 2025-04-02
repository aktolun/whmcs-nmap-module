<?php

declare(strict_types=1);

use WHMCS\Database\Capsule;

if (!defined("WHMCS")) {
    die("Bu dosyaya doğrudan erişim yasaktır.");
}

require_once __DIR__ . '/securityscanner.php';

add_hook('PreCronJob', 1, function($vars) {
    try {
        logActivity('Güvenlik Tarayıcı: PreCronJob tetiklendi - ' . date('Y-m-d H:i:s'));
        
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
        
        logActivity('Güvenlik Tarayıcı: Ayarlar - Interval: ' . $scanInterval . ', Time: ' . $scanTime . ', Last: ' . $lastScanTime);
        
        $currentTime = time();
        $currentHour = (int)date('H', $currentTime);
        $currentMinute = (int)date('i', $currentTime);
        list($targetHour, $targetMinute) = explode(':', $scanTime);
        
        logActivity('Güvenlik Tarayıcı: Zaman kontrolü - Current: ' . $currentHour . ':' . $currentMinute . ', Target: ' . $targetHour . ':' . $targetMinute);
        
        if ($scanInterval === 3600) {
            if (abs($currentMinute - (int)$targetMinute) > 1) {
                logActivity('Güvenlik Tarayıcı: Saatlik tarama için dakika kontrolü başarısız.');
                return;
            }
            logActivity('Güvenlik Tarayıcı: Saatlik tarama için dakika kontrolü başarılı.');
        } else {
            if (abs($currentHour - (int)$targetHour) > 0 || abs($currentMinute - (int)$targetMinute) > 1) {
                logActivity('Güvenlik Tarayıcı: Tarama saati henüz gelmedi.');
                return;
            }
        }
        
        if (!empty($lastScanTime)) {
            $lastScan = strtotime($lastScanTime);
            $timeDiff = $currentTime - $lastScan;
            
            logActivity('Güvenlik Tarayıcı: Son tarama kontrolü - Geçen süre: ' . $timeDiff . ' saniye');
            
            if ($timeDiff < $scanInterval) {
                logActivity('Güvenlik Tarayıcı: Tarama aralığı henüz dolmadı.');
                return;
            }
        }
        
        $result = securityscanner_startScan($vars);
        
        if ($result['success']) {
            logActivity('Güvenlik Tarayıcı: Tarama başarıyla başlatıldı');
            Capsule::table('tbladdonmodules')
                ->where('module', 'securityscanner')
                ->where('setting', 'last_scan_time')
                ->update(['value' => date('Y-m-d H:i:s')]);
        } else {
            logActivity('Güvenlik Tarayıcı: Tarama başlatılamadı - ' . $result['error']);
        }
    } catch (\Exception $e) {
        logActivity('Güvenlik Tarayıcı PreCronJob Hatası: ' . $e->getMessage());
    }
}); 