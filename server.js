require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { exec } = require('child_process');
const fs = require('fs').promises; // Promise versiyonunu kullan
const path = require('path');
const util = require('util');
const xml2js = require('xml2js');

const app = express();
const PORT = process.env.PORT || 3000;
const API_KEY = process.env.API_KEY;
const SCAN_TIMEOUT = 600000; // 10 dakika

const execPromise = util.promisify(exec);
const parser = new xml2js.Parser();

// Middleware
app.use(cors());
app.use(express.json());

// Timeout middleware
app.use((req, res, next) => {
    res.setTimeout(SCAN_TIMEOUT, () => {
        res.status(408).json({ error: 'İstek zaman aşımına uğradı' });
    });
    next();
});

// API Key kontrolü
const checkApiKey = (req, res, next) => {
    const apiKey = req.headers.authorization?.split(' ')[1];
    if (!apiKey || apiKey !== API_KEY) {
        return res.status(401).json({ error: 'Geçersiz API anahtarı' });
    }
    next();
};

// Scans dizinini oluştur
const scansDir = path.join(__dirname, 'scans');
(async () => {
    try {
        await fs.mkdir(scansDir, { recursive: true, mode: 0o777 });
        console.log('Scans dizini oluşturuldu:', scansDir);
    } catch (error) {
        console.error('Scans dizini oluşturma hatası:', error);
    }
})();

// Dizin izinlerini kontrol et
(async () => {
    try {
        await fs.access(scansDir, fs.constants.W_OK);
        console.log('Scans dizini yazılabilir');
    } catch (error) {
        console.error('Scans dizini yazılabilir değil!');
        console.error('Hata:', error);
        // Dizin izinlerini düzeltmeyi dene
        try {
            await fs.chmod(scansDir, 0o777);
            console.log('Scans dizini izinleri düzeltildi');
        } catch (chmodError) {
            console.error('İzin düzeltme hatası:', chmodError);
        }
    }
})();

// Nmap'in yüklü olup olmadığını kontrol et
exec('which nmap', (error, stdout, stderr) => {
    if (error) {
        console.error('Nmap yüklü değil!');
        console.error('Hata:', error);
    } else {
        console.log('Nmap yüklü:', stdout.trim());
    }
});

// XML'i JSON'a çevir
async function parseXML(xmlData) {
    try {
        const result = await parser.parseStringPromise(xmlData);
        const nmaprun = result.nmaprun;
        
        if (!nmaprun || !nmaprun.host || !nmaprun.host[0]) {
            throw new Error('Geçersiz XML formatı');
        }

        const host = nmaprun.host[0];
        const address = host.address?.[0]?.$?.addr || '';
        const hostname = host.hostnames?.[0]?.hostname?.[0]?.$?.name || '';
        
        // Tarama ID'sini timestamp olarak oluştur
        const scanId = Date.now().toString();
        
        const scanResults = {
            scan_id: scanId,
            ip_address: address,
            hostname: hostname,
            ports: [],
            vulnerabilities: [],
            nmap_output: nmaprun.runstats?.[0]?.finished?.[0]?.$.summary || '',
            status: 'completed',
            timestamp: new Date().toISOString()
        };

        // Port bilgilerini işle
        if (host.ports && host.ports[0] && host.ports[0].port) {
            for (const port of host.ports[0].port) {
                if (!port || !port.$ || !port.state || !port.state[0]) continue;

                const portInfo = {
                    port: port.$.portid,
                    state: port.state[0].$.state,
                    service: port.service?.[0]?.$.name || '',
                    version: port.service?.[0]?.$.product || ''
                };
                scanResults.ports.push(portInfo);

                // Zafiyet bilgilerini işle
                if (port.script && port.script[0] && port.script[0].$.id === 'vulners') {
                    const vulnTable = port.script[0].table?.[0]?.table || [];
                    
                    for (const vuln of vulnTable) {
                        if (!vuln || !vuln.elem) continue;
                        
                        const elements = {};
                        for (const elem of vuln.elem) {
                            if (elem.$ && elem.$.key) {
                                elements[elem.$.key] = elem._;
                            }
                        }
                        
                        if (elements.id && elements.cvss) {
                            scanResults.vulnerabilities.push({
                                port: port.$.portid,
                                cve: elements.id,
                                cvss: elements.cvss,
                                description: `https://vulners.com/${elements.type}/${elements.id}`,
                                is_exploit: elements.is_exploit === 'true'
                            });
                        }
                    }
                }
            }
        }

        return scanResults;
    } catch (error) {
        console.error('XML işleme hatası:', error);
        return {
            scan_id: Date.now().toString(),
            ip_address: '',
            hostname: '',
            ports: [],
            vulnerabilities: [],
            nmap_output: '',
            status: 'failed',
            error: error.message,
            timestamp: new Date().toISOString()
        };
    }
}

// Tarama işlemini arka planda çalıştır
async function runScan(ipAddress, scanId, jsonFile, xmlFile) {
    try {
        console.log('Tarama başlatılıyor:', { ipAddress, scanId, jsonFile, xmlFile });
        
        // Nmap komutunu çalıştır - basitleştirilmiş komut
        const command = `nmap -sV --script vuln ${ipAddress} -oX ${xmlFile}`;
        console.log('Nmap komutu:', command);
        
        const { stdout, stderr } = await execPromise(command);
        console.log('Nmap çıktısı:', stdout);
        
        if (stderr) {
            console.error('Nmap hata çıktısı:', stderr);
        }

        // XML dosyasını kontrol et
        try {
            await fs.access(xmlFile);
        } catch {
            console.log('XML dosyası oluşturulamadı, Nmap çıktısını işle');
            
            // Nmap çıktısını işle
            const lines = stdout.split('\n');
            const results = {
                scan_id: scanId,
                ip_address: ipAddress,
                hostname: '',
                ports: [],
                vulnerabilities: [],
                nmap_output: stdout,
                status: 'completed',
                timestamp: new Date().toISOString()
            };
            
            let currentPort = null;
            let vulnSection = false;
            
            for (const line of lines) {
                // Hostname bilgisini al
                const hostnameMatch = line.match(/Nmap scan report for (.+?) \((.+?)\)/);
                if (hostnameMatch) {
                    results.hostname = hostnameMatch[1];
                    results.ip_address = hostnameMatch[2];
                }
                
                // Port bilgilerini al
                const portMatch = line.match(/(\d+)\/tcp\s+(\w+)\s+(\w+)\s+(.+)/);
                if (portMatch) {
                    currentPort = {
                        port: portMatch[1],
                        state: portMatch[2],
                        service: portMatch[3],
                        version: portMatch[4]
                    };
                    results.ports.push(currentPort);
                    vulnSection = false;
                }
                
                // Zafiyet bilgilerini al
                if (line.includes('vuln:')) {
                    vulnSection = true;
                } else if (vulnSection && line.trim()) {
                    // Zafiyet satırını işle
                    const vulnLine = line.trim();
                    if (vulnLine.startsWith('|')) {
                        const parts = vulnLine.split(/\s+/);
                        if (parts.length >= 3) {
                            const cve = parts[0].replace('|', '').trim();
                            const cvss = parts[1];
                            const url = parts[2];
                            
                            if (cve && cvss && url && currentPort) {
                                results.vulnerabilities.push({
                                    port: currentPort.port,
                                    cve: cve,
                                    cvss: cvss,
                                    description: url
                                });
                            }
                        }
                    }
                }
            }
            
            // Sonuçları JSON dosyasına kaydet
            await fs.writeFile(jsonFile, JSON.stringify(results, null, 2));
            console.log('Sonuçlar JSON dosyasına kaydedildi:', jsonFile);
            
            return results;
        }
        
        // XML dosyası varsa, XML'i işle
        const xmlData = await fs.readFile(xmlFile, 'utf8');
        const result = await parseXML(xmlData);
        result.scan_id = scanId; // Tarama ID'sini koru
        result.status = 'completed';
        
        // Sonuçları JSON dosyasına kaydet
        await fs.writeFile(jsonFile, JSON.stringify(result, null, 2));
        console.log('Sonuçlar JSON dosyasına kaydedildi:', jsonFile);
        
        return result;
    } catch (error) {
        console.error('Tarama hatası:', error);
        const errorResult = {
            scan_id: scanId,
            ip_address: ipAddress,
            status: 'failed',
            error: error.message,
            timestamp: new Date().toISOString()
        };
        await fs.writeFile(jsonFile, JSON.stringify(errorResult, null, 2));
        return errorResult;
    }
}

// Tarama başlatma
app.post('/scan', checkApiKey, async (req, res) => {
    const { ip } = req.body;
    if (!ip) {
        return res.status(400).json({ error: 'IP adresi gerekli' });
    }

    const scanId = Date.now().toString();
    const baseFileName = scanId;
    const jsonFile = path.join(__dirname, 'scans', `${baseFileName}.json`);
    const xmlFile = path.join(__dirname, 'scans', `${baseFileName}.xml`);

    try {
        // Başlangıç durumunu kaydet
        const initialStatus = {
            scan_id: scanId,
            ip_address: ip,
            status: 'running',
            timestamp: new Date().toISOString()
        };
        await fs.writeFile(jsonFile, JSON.stringify(initialStatus, null, 2));

        // Taramayı arka planda başlat
        runScan(ip, scanId, jsonFile, xmlFile).catch(error => {
            console.error('Tarama hatası:', error);
            const errorStatus = {
                ...initialStatus,
                status: 'failed',
                error: error.message
            };
            fs.writeFile(jsonFile, JSON.stringify(errorStatus, null, 2));
        });

        // Hemen yanıt döndür
        res.json({ 
            scan_id: scanId,
            status: 'running',
            message: 'Tarama başlatıldı'
        });
    } catch (error) {
        console.error('Tarama başlatma hatası:', error);
        res.status(500).json({ 
            error: error.message,
            scan_id: scanId
        });
    }
});

// Tarama durumu kontrolü
app.get('/status/:scanId', checkApiKey, async (req, res) => {
    const { scanId } = req.params;
    const outputFile = path.join(__dirname, 'scans', `${scanId}.json`);

    try {
        await fs.access(outputFile);
        const results = JSON.parse(await fs.readFile(outputFile, 'utf8'));
        res.json({ 
            status: results.status,
            scan_id: scanId
        });
    } catch (error) {
        if (error.code === 'ENOENT') {
            res.status(404).json({ error: 'Tarama bulunamadı' });
        } else {
            console.error('Durum kontrolü hatası:', error);
            res.json({ 
                status: 'failed', 
                error: error.message,
                scan_id: scanId
            });
        }
    }
});

// Tamamlanan taramaları getir
app.get('/completed-scans', checkApiKey, async (req, res) => {
    try {
        console.log('Tamamlanan taramalar isteniyor...');
        console.log('Scans dizini:', scansDir);
        
        // Dizin varlığını kontrol et
        try {
            await fs.access(scansDir);
        } catch (error) {
            console.error('Scans dizini bulunamadı:', error);
            return res.json({ success: true, scans: [] });
        }
        
        const files = await fs.readdir(scansDir);
        console.log('Bulunan dosyalar:', files);
        
        if (files.length === 0) {
            console.log('Dizinde dosya bulunamadı');
            return res.json({ success: true, scans: [] });
        }
        
        const scans = await Promise.all(
            files
                .filter(file => file.endsWith('.json'))
                .map(async file => {
                    try {
                        const filePath = path.join(scansDir, file);
                        console.log('Dosya okunuyor:', filePath);
                        
                        const content = JSON.parse(await fs.readFile(filePath, 'utf8'));
                        console.log('Dosya içeriği:', content);
                        
                        const scanId = content.scan_id || path.parse(file).name.replace('.json', '');
                        
                        // Tarama durumunu kontrol et
                        const status = content.status || 'unknown';
                        
                        // Tarih bilgisini JSON'dan al
                        let timestamp = content.timestamp;
                        if (!timestamp && scanId) {
                            try {
                                // scanId timestamp ise, tarihe dönüştür
                                const date = new Date(parseInt(scanId));
                                if (!isNaN(date.getTime())) {
                                    timestamp = date.toISOString();
                                } else {
                                    timestamp = new Date().toISOString();
                                }
                            } catch (error) {
                                console.error('Tarih dönüşüm hatası:', error);
                                timestamp = new Date().toISOString();
                            }
                        }
                        
                        const scan = {
                            id: scanId,
                            ip_address: content.ip_address || 'Unknown',
                            start_date: timestamp || new Date().toISOString(),
                            status: status
                        };
                        
                        console.log('İşlenen tarama:', scan);
                        return scan;
                    } catch (error) {
                        console.error(`Dosya okuma hatası (${file}):`, error);
                        return null;
                    }
                })
        );
        
        // Geçersiz sonuçları filtrele
        const validScans = scans.filter(scan => scan !== null);
        console.log('Geçerli taramalar:', validScans);
        
        // Tarihe göre sırala (en yeniden en eskiye)
        validScans.sort((a, b) => new Date(b.start_date) - new Date(a.start_date));
        
        res.json({ 
            success: true,
            scans: validScans
        });
    } catch (error) {
        console.error('Tamamlanan taramaları getirme hatası:', error);
        res.status(500).json({ 
            success: false,
            error: 'Tamamlanan taramalar alınamadı' 
        });
    }
});

// Tarama sonuçlarını getir
app.get('/results/:scanId', checkApiKey, async (req, res) => {
    const { scanId } = req.params;
    const outputFile = path.join(__dirname, 'scans', `${scanId}.json`);

    try {
        console.log('Tarama sonuçları isteniyor:', scanId);
        console.log('Dosya yolu:', outputFile);
        
        // Dosya varlığını kontrol et
        try {
            await fs.access(outputFile);
        } catch (error) {
            console.error('Dosya bulunamadı:', error);
            return res.status(404).json({ 
                success: false,
                error: 'Tarama bulunamadı' 
            });
        }
        
        // Dosyayı oku
        const fileContent = await fs.readFile(outputFile, 'utf8');
        console.log('Dosya içeriği:', fileContent);
        
        const results = JSON.parse(fileContent);
        console.log('Okunan sonuçlar:', results);
        
        // Sonuçları başarılı yanıt olarak döndür
        res.json({
            success: true,
            scan_id: scanId,
            ip_address: results.ip_address || '',
            timestamp: results.timestamp || new Date().toISOString(),
            ports: results.ports || [],
            vulnerabilities: results.vulnerabilities || [],
            nmap_output: results.nmap_output || ''
        });
    } catch (error) {
        console.error('Sonuç okuma hatası:', error);
        res.status(500).json({ 
            success: false,
            error: 'Sonuçlar okunamadı' 
        });
    }
});

app.listen(PORT, () => {
    console.log(`API sunucusu ${PORT} portunda çalışıyor`);
    console.log('API Key:', API_KEY ? 'Ayarlanmış' : 'Ayarlanmamış');
}); 