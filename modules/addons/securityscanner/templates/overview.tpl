{* Güvenlik Tarayıcı Ana Sayfa Template'i *}

<div class="row">
    <div class="col-md-4">
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">Güvenlik Tarayıcı Ayarları</h3>
            </div>
            <div class="card-body">
                <form id="settingsForm" method="post">
                    <div class="form-group">
                        <label class="control-label">Tarama Aralığı</label>
                        <select name="scan_interval" class="form-control">
                            <option value="3600" {if $settings.scan_interval == 3600}selected{/if}>Her Saat</option>
                            <option value="86400" {if $settings.scan_interval == 86400}selected{/if}>Her Gün</option>
                            <option value="604800" {if $settings.scan_interval == 604800}selected{/if}>Her Hafta</option>
                            <option value="2592000" {if $settings.scan_interval == 2592000}selected{/if}>Her Ay</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label class="control-label">Tarama Saati</label>
                        <input type="text" name="scan_time" class="form-control" value="{$settings.scan_time}" placeholder="HH:mm">
                    </div>
                    <div class="form-group">
                        <button type="submit" class="btn btn-primary btn-sm">Ayarları Kaydet</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <div class="col-md-4">
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">Aktif IP'lerden Tarama</h3>
            </div>
            <div class="card-body">
                <form id="scanForm" method="post">
                    <div class="form-group">
                        <label class="control-label">IP Adresi Seçin</label>
                        <select name="ip" class="form-control" required>
                            <option value="">Seçiniz...</option>
                            {foreach from=$activeIps item=ip}
                                <option value="{$ip.ip}">{$ip.ip}</option>
                            {/foreach}
                        </select>
                    </div>
                    <div class="form-group">
                        <button type="submit" class="btn btn-primary btn-sm">Taramayı Başlat</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <div class="col-md-4">
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">Özel IP Tarama</h3>
            </div>
            <div class="card-body">
                <form id="customScanForm" method="post">
                    <div class="form-group">
                        <label class="control-label">IP Adresi</label>
                        <input type="text" name="custom_ip" class="form-control" placeholder="Örn: 192.168.1.1" required>
                    </div>
                    <div class="form-group">
                        <button type="submit" class="btn btn-primary btn-sm">Taramayı Başlat</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
</div>

{if $scanStatus}
<div class="row mt-4">
    <div class="col-md-12">
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">Tarama Durumu</h3>
            </div>
            <div class="card-body">
                <div id="scanStatus">
                    <div class="progress">
                        <div class="progress-bar progress-bar-striped active" role="progressbar" style="width: 100%">
                            {$scanStatus.status}
                        </div>
                    </div>
                    <div id="scanResults" class="mt-3"></div>
                </div>
            </div>
        </div>
    </div>
</div>
{/if}

<div class="row mt-4">
    <div class="col-md-12">
        <div class="card">
            <div class="card-header">
                <div class="d-flex justify-content-between align-items-center">
                    <h3 class="card-title mb-0">Tamamlanan Taramalar</h3>
                    <div class="ml-auto" style="width: 300px;">
                        <input type="text" id="searchInput" class="form-control" placeholder="IP adresine göre ara...">
                    </div>
                </div>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <th>IP Adresi</th>
                                <th>Tarama Tarihi</th>
                                <th>Durum</th>
                                <th>İşlemler</th>
                            </tr>
                        </thead>
                        <tbody id="scanTableBody">
                            {foreach from=$completedScans item=scan}
                                <tr>
                                    <td>{$scan.ip_address}</td>
                                    <td>{$scan.scan_date}</td>
                                    <td>{$scan.status}</td>
                                    <td>
                                        <button class="btn btn-sm btn-info view-details" data-scan-id="{$scan.id}">
                                            Detayları Görüntüle
                                        </button>
                                    </td>
                                </tr>
                            {/foreach}
                        </tbody>
                    </table>
                </div>
                <nav aria-label="Sayfalama" class="mt-3">
                    <ul class="pagination justify-content-center" id="pagination">
                    </ul>
                </nav>
            </div>
        </div>
    </div>
</div>

<!-- Sonuç Modal -->
<div class="modal fade" id="scanResultsModal" tabindex="-1" role="dialog" aria-labelledby="scanResultsModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-lg" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="scanResultsModalLabel">Tarama Sonuçları</h5>
                <button type="button" class="close" data-dismiss="modal" aria-label="Kapat">
                    <span aria-hidden="true">&times;</span>
                </button>
            </div>
            <div class="modal-body">
                <div class="row">
                    <div class="col-md-12">
                        <div class="card">
                            <div class="card-body">
                                <div class="scan-info mb-3">
                                    <h6>Tarama Bilgileri</h6>
                                    <table class="table table-sm">
                                        <tr>
                                            <th>IP Adresi:</th>
                                            <td id="modalIpAddress"></td>
                                        </tr>
                                        <tr>
                                            <th>Tarama Tarihi:</th>
                                            <td id="modalScanDate"></td>
                                        </tr>
                                        <tr>
                                            <th>Durum:</th>
                                            <td id="modalStatus"></td>
                                        </tr>
                                    </table>
                                </div>
                                <div class="scan-results">
                                    <h6>Tarama Sonuçları</h6>
                                    <pre id="modalResults" class="bg-light p-3 rounded"></pre>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
$(document).ready(function() {
    $('#settingsForm').on('submit', function(e) {
        e.preventDefault();
        $.ajax({
            url: '{$modulelink}&action=savesettings',
            method: 'POST',
            data: $(this).serialize(),
            dataType: 'json',
            success: function(response) {
                if (response.success) {
                    alert('Ayarlar başarıyla kaydedildi.');
                    location.reload();
                } else {
                    alert('Hata: ' + response.error);
                }
            },
            error: function(xhr, status, error) {
                alert('Bir hata oluştu: ' + error);
            }
        });
    });

    $('#scanForm').on('submit', function(e) {
        e.preventDefault();
        $.ajax({
            url: '{$modulelink}&action=startscan',
            method: 'POST',
            data: $(this).serialize(),
            dataType: 'json',
            success: function(response) {
                if (response.success) {
                    alert('Tarama başlatıldı. Scan ID: ' + response.scan_id);
                    checkStatus(response.scan_id);
                } else {
                    alert('Hata: ' + response.error);
                }
            },
            error: function(xhr, status, error) {
                alert('Bir hata oluştu: ' + error);
            }
        });
    });

    $('#customScanForm').on('submit', function(e) {
        e.preventDefault();
        $.ajax({
            url: '{$modulelink}&action=startscan',
            method: 'POST',
            data: $(this).serialize(),
            dataType: 'json',
            success: function(response) {
                if (response.success) {
                    alert('Tarama başlatıldı. Scan ID: ' + response.scan_id);
                    checkStatus(response.scan_id);
                } else {
                    alert('Hata: ' + response.error);
                }
            },
            error: function(xhr, status, error) {
                alert('Bir hata oluştu: ' + error);
            }
        });
    });

    $('.view-details').on('click', function() {
        var scanId = $(this).data('scan-id');
        viewResults(scanId);
    });

    $('#searchInput').on('keyup', function() {
        var searchText = $(this).val().toLowerCase();
        $('#scanTableBody tr').each(function() {
            var ipAddress = $(this).find('td:first').text().toLowerCase();
            if (ipAddress.includes(searchText)) {
                $(this).show();
            } else {
                $(this).hide();
            }
        });
    });
});

function checkStatus(scanId) {
    $.ajax({
        url: '{$modulelink}&action=checkstatus',
        method: 'POST',
        data: { scan_id: scanId },
        dataType: 'json',
        success: function(response) {
            if (response.success) {
                $('#scanStatus').html('<div class="alert alert-info">' + response.status + '</div>');
                if (response.status === 'completed') {
                    viewResults(scanId);
                } else if (response.status !== 'failed') {
                    setTimeout(function() {
                        checkStatus(scanId);
                    }, 5000);
                }
            } else {
                $('#scanStatus').html('<div class="alert alert-danger">' + response.error + '</div>');
            }
        },
        error: function(xhr, status, error) {
            $('#scanStatus').html('<div class="alert alert-danger">Durum kontrolünde hata: ' + error + '</div>');
        }
    });
}

function viewResults(scanId) {
    $.ajax({
        url: '{$modulelink}&action=getresults',
        method: 'POST',
        data: { scan_id: scanId },
        dataType: 'json',
        success: function(response) {
            if (response.success) {
                try {
                    var results = JSON.parse(response.results);
                    $('#modalIpAddress').text(results.ip_address);
                    $('#modalScanDate').text(results.scan_date);
                    $('#modalStatus').text(results.status);
                    $('#modalResults').text(JSON.stringify(results.scan_results, null, 2));
                    $('#scanResultsModal').modal('show');
                } catch (e) {
                    console.error('Sonuçlar parse edilemedi:', e);
                    alert('Sonuçlar görüntülenirken bir hata oluştu.');
                }
            } else {
                alert('Hata: ' + response.error);
            }
        },
        error: function(xhr, status, error) {
            console.error('AJAX hatası:', error);
            alert('Sonuçlar alınırken bir hata oluştu.');
        }
    });
}
</script> 