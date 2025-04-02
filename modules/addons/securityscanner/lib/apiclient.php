<?php

declare(strict_types=1);

use WHMCS\Database\Capsule;

class Apiclient
{
    private string $apiUrl;
    private string $apiKey;
    private array $config;

    public function __construct(array $vars)
    {
        $this->config = $this->getConfig();
        $this->apiUrl = rtrim($this->config['api_url'], '/');
        $this->apiKey = $this->config['api_key'];

        if (empty($this->apiKey)) {
            throw new \Exception('API anahtarı yapılandırılmamış. Lütfen modül ayarlarından API anahtarını girin.');
        }
    }

    /**
     * IP adresinin geçerli olup olmadığını kontrol eder
     * 
     * @param string $ipAddress Kontrol edilecek IP adresi
     * @return bool IP adresi geçerli ise true, değilse false
     */
    private function validateIpAddress(string $ipAddress): bool
    {
        return filter_var($ipAddress, FILTER_VALIDATE_IP) !== false;
    }

    /**
     * IP adresini temizler ve güvenlik kontrollerinden geçirir
     * 
     * @param string $ipAddress Temizlenecek IP adresi
     * @return string|false Temizlenmiş IP adresi veya geçersizse false
     */
    private function sanitizeIpAddress(string $ipAddress)
    {
        // Sadece geçerli IP karakterlerine izin ver (rakamlar, noktalar, iki nokta üst üste)
        $ipAddress = preg_replace('/[^\d\.:a-fA-F]/', '', $ipAddress);
        
        // Temizlenen IP hala geçerli mi kontrol et
        if ($this->validateIpAddress($ipAddress)) {
            return $ipAddress;
        }
        
        return false;
    }

    private function getConfig(): array
    {
        $config = [];
        try {
            $results = Capsule::table('tbladdonmodules')
                ->where('module', 'securityscanner')
                ->select('setting', 'value')
                ->get();
                
            foreach ($results as $row) {
                $config[$row->setting] = $row->value;
            }
        } catch (\Exception $e) {
            logActivity('Güvenlik Tarayıcı: Yapılandırma erişim hatası - ' . $e->getMessage());
        }
        return $config;
    }

    /**
     * IP adresi için tarama başlatır
     *
     * @param string $ipAddress Taranacak IP adresi
     * @return string Tarama ID'si
     * @throws Apiexception
     */
    public function scanIp(string $ipAddress): string
    {
        try {
            // Tarama başlat
            return $this->startScan($ipAddress)['scan_id'];
        } catch (\Exception $e) {
            throw new Apiexception("Tarama hatası: " . $e->getMessage());
        }
    }

    /**
     * Yeni bir tarama başlatır
     *
     * @param string $ipAddress Taranacak IP adresi
     * @return array Tarama bilgilerini içeren dizi
     * @throws \Exception IP adresi geçersizse veya API hatası oluşursa
     */
    public function startScan(string $ipAddress): array
    {
        try {
            // IP adresini doğrula
            if (!$this->validateIpAddress($ipAddress)) {
                throw new \Exception('Geçersiz IP adresi formatı');
            }

            // IP adresini temizle
            $cleanIpAddress = $this->sanitizeIpAddress($ipAddress);
            if ($cleanIpAddress === false) {
                throw new \Exception('IP adresi temizlendikten sonra geçersiz hale geldi');
            }

            // API isteği için veriyi hazırla
            $data = [
                'ip' => $cleanIpAddress,
                'scan_options' => [
                    'ping' => true,
                    'service_detection' => true,
                    'vulnerability_detection' => true,
                    'min_cvss' => 5.0,
                    'port_range' => 'all'
                ]
            ];

            // API isteğini gönder
            $response = $this->makeRequest('POST', '/scan', $data);

            // API yanıtını logla
            logActivity('Güvenlik Tarayıcı: API yanıtı - ' . json_encode($response));

            if (!isset($response['scan_id'])) {
                throw new \Exception('API yanıtında scan_id bulunamadı');
            }

            // Tarama durumunu kontrol et
            $statusResult = $this->getScanStatus($response['scan_id']);
            
            // Durumu logla
            logActivity('Güvenlik Tarayıcı: Tarama durumu - ' . json_encode($statusResult));

            return [
                'success' => true,
                'scan_id' => $response['scan_id'],
                'status' => $statusResult['success'] ? $statusResult['status'] : 'error',
                'message' => 'Tarama başarıyla başlatıldı'
            ];

        } catch (\Exception $e) {
            logActivity('Güvenlik Tarayıcı: Tarama başlatma hatası - ' . $e->getMessage());
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }

    /**
     * Tarama durumunu kontrol eder
     *
     * @param string $scanId Tarama ID'si
     * @return string Durum bilgisi
     * @throws Apiexception
     */
    public function checkScanStatus(string $scanId): string
    {
        $response = $this->getScanStatus($scanId);
        
        if (!$response['success']) {
            throw new Apiexception("API Hatası: " . $response['error']);
        }

        return $response['status'];
    }

    /**
     * Tarama sonuçlarını getirir
     *
     * @param string $scanId Tarama ID'si
     * @return array Tarama sonuçları
     * @throws Apiexception
     */
    public function getScanResults(string $scanId): array
    {
        try {
            $response = $this->makeRequest('GET', "/results/{$scanId}");
            
            // API yanıtını kontrol et
            if (!$response['success']) {
                return [
                    'success' => false,
                    'error' => $response['error'] ?? 'Sonuçlar alınamadı'
                ];
            }

            // WHMCS formatına dönüştür
            return [
                'success' => true,
                'results' => [
                    'scan_id' => $scanId,
                    'ip_address' => $response['ip_address'] ?? '',
                    'timestamp' => $response['timestamp'] ?? date('Y-m-d H:i:s'),
                    'ports' => $response['ports'] ?? [],
                    'vulnerabilities' => $response['vulnerabilities'] ?? [],
                    'services' => $response['services'] ?? [],
                    'os' => $response['os'] ?? '',
                    'summary' => $response['summary'] ?? ''
                ]
            ];
        } catch (\Exception $e) {
            logActivity("Security Scanner API Hatası: " . $e->getMessage());
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }

    public function getScanStatus(string $scanId): array
    {
        try {
            $response = $this->makeRequest('GET', "/status/{$scanId}");
            
            // Node.js API'sinden gelen yanıtı kontrol et
            if (isset($response['status'])) {
                return [
                    'success' => true,
                    'status' => $response['status'],
                    'message' => $response['message'] ?? ''
                ];
            }

            return [
                'success' => false,
                'error' => 'API yanıtında durum bulunamadı'
            ];
        } catch (\Exception $e) {
            logActivity('Güvenlik Tarayıcı: Durum alma hatası - ' . $e->getMessage());
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }

    public function getCompletedScans(): array
    {
        try {
            $response = $this->makeRequest('GET', '/completed-scans');
            
            // API yanıtını kontrol et
            if (!$response['success']) {
                return [
                    'success' => false,
                    'error' => $response['error'] ?? 'Tamamlanan taramalar alınamadı'
                ];
            }

            // Her tarama için durumu kontrol et
            $scans = [];
            foreach ($response['scans'] as $scan) {
                $scans[] = [
                    'id' => $scan['id'],
                    'ip_address' => $scan['ip_address'],
                    'start_date' => $scan['start_date'],
                    'status' => $scan['status']
                ];
            }

            return [
                'success' => true,
                'scans' => $scans
            ];
        } catch (\Exception $e) {
            logActivity('Security Scanner API Hatası: ' . $e->getMessage());
            return [
                'success' => false,
                'error' => 'API Hatası: ' . $e->getMessage()
            ];
        }
    }

    /**
     * API'ye istek gönderir
     *
     * @param string $method HTTP metodu (GET, POST, vb.)
     * @param string $endpoint API endpoint'i
     * @param array $data İstek verisi
     * @return array API yanıtı
     * @throws \Exception API hatası durumunda
     */
    private function makeRequest(string $method, string $endpoint, array $data = []): array
    {
        try {
            $url = $this->apiUrl . $endpoint;
            
            // cURL oturumunu başlat
            $ch = curl_init();
            
            // cURL seçeneklerini ayarla
            $headers = [
                'Content-Type: application/json',
                'Authorization: Bearer ' . $this->apiKey
            ];
            
            $options = [
                CURLOPT_URL => $url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => 30,
                CURLOPT_HTTPHEADER => $headers,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2
            ];
            
            // POST isteği için veriyi ekle
            if ($method === 'POST') {
                $options[CURLOPT_POST] = true;
                $options[CURLOPT_POSTFIELDS] = json_encode($data);
            } elseif ($method !== 'GET') {
                $options[CURLOPT_CUSTOMREQUEST] = $method;
                if (!empty($data)) {
                    $options[CURLOPT_POSTFIELDS] = json_encode($data);
                }
            }
            
            // İsteği gönder ve yanıtı al
            curl_setopt_array($ch, $options);
            
            $response = curl_exec($ch);
            $responseCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $error = curl_error($ch);
            $errno = curl_errno($ch);
            
            // cURL oturumunu kapat
            curl_close($ch);
            
            if ($errno) {
                throw new \Exception("cURL Hatası ({$errno}): {$error}");
            }
            
            // İsteği ve yanıtı logla
            logActivity('Güvenlik Tarayıcı: API İsteği - ' . $method . ' ' . $url);
            logActivity('Güvenlik Tarayıcı: API İstek Verisi - ' . json_encode($data));
            logActivity('Güvenlik Tarayıcı: API Yanıt Kodu - ' . $responseCode);
            logActivity('Güvenlik Tarayıcı: API Yanıt - ' . $response);
            
            if ($responseCode >= 400) {
                throw new \Exception("HTTP Hata Kodu: {$responseCode}, Mesaj: " . ($response['error'] ?? 'Bilinmeyen hata'));
            }
            
            // JSON yanıtını decode et
            $decodedResponse = json_decode($response, true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                throw new \Exception("API yanıtı JSON formatında değil: " . json_last_error_msg());
            }
            
            return $decodedResponse;
            
        } catch (\Exception $e) {
            logActivity('Güvenlik Tarayıcı: API isteği hatası - ' . $e->getMessage());
            throw $e;
        }
    }
} 