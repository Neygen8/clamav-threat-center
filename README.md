# ClamAV canlı koruma (macOS)

Bu proje ClamAV'ı sürekli çalışan, yerel bir koruma katmanı hâline getirir.
Kurulumdan sonra altı kullanıcı görevi oturum açıldığında otomatik başlar:

- `clamd`, virüs veritabanını bellekte tutarak dosyaları hızlı tarar.
- Canlı izleyici `Desktop` ve `Downloads` altındaki yeni veya değişen dosyaları
  algılar. Haricî diskler yalnızca açıkça seçildiğinde taranır; bu, pildeyken
  gereksiz disk erişimini önler.
- Dosyanın yazılması bitince tarama yapılır; aynı dosya olayları birleştirilir ve
  taramalar sistem yükünü sınırlamak için sırayla çalıştırılır.
- Servis yeniden başlatıldığında geçmiş dosyalar yeniden sıraya alınmaz; yalnız
  yeni değişiklikler izlenir. Olay akışı gerçekten kesilirse sınırlı telafi
  taraması devreye girer.
- Disk imajları ve arşivler (`.dmg`, `.iso`, `.zip`, `.jar`, `.7z`, `.rar` ve
  benzerleri) canlı taramada açılmaz; Gatekeeper ve VirusTotal hash kontrolü
  devam eder. Bunları gerekirse Finder'daki **ClamAV ile Tara** eylemiyle
  isteğe bağlı derin tarayabilirsin.
- Bulunan tehdit, izinleri yalnızca kullanıcıya açık olan karantinaya otomatik
  taşınır. Uyumlu JSON bilgisi sayesinde Tehdit Merkezi'nden görülebilir ve geri
  yüklenebilir.
- Virüs imzaları her 6 saatte bir güncellenir ve çalışan `clamd` motoruna yeniden
  yüklenir.
- Ek olarak `Desktop` ve `Downloads` her gün 19:00'da tam taranır.
- VirusTotal ikinci görüş hizmeti ayrı bir menü çubuğu uygulaması açmadan
  `Downloads` klasörünü izler ve sonuçlarını aynı kontrol paneline gönderir.
- Birleşik Tehdit Merkezi arayüzü sağ üst menü çubuğunda kalkan simgesiyle
  başlar; ClamAV, canlı koruma ve VirusTotal durumu buradan görülüp panel açılabilir.

Finder'da bir dosya veya klasöre sağ tıklayıp **Hızlı Eylemler > ClamAV ile Tara**
seçeneğiyle isteğe bağlı tarama yapılabilir. **ClamAV Tehdit Merkezi** içindeki
**Kontrol Paneli**, ClamAV motoru, canlı izleyici, VirusTotal ve diğer koruma
katmanlarını tek yerde gösterir. Yalnız bu projeye ait servisler panelden güvenli
biçimde yeniden başlatılır; üçüncü taraf korumaların kendi ayar uygulamaları açılır.
Uygulama `~/Applications` içine kurulur.
Menüdeki **Arayüzden Çık** yalnız görsel uygulamayı kapatır; koruma
servisleri ayrı arka plan görevleri olarak çalışmaya devam eder.

> Bu izleyici dosya diske yazıldıktan hemen sonra tarar. Apple Endpoint Security
> yetkisi kullanan Santa gibi bir çalıştırma engelleyicinin yerini tutmaz ve her
> dosyanın açılmadan önce durdurulacağını garanti etmez.

## Savunma katmanları

Tehdit Merkezi aşağıdaki tamamlayıcı katmanların sağlık durumunu da gösterir:

- macOS Gatekeeper ve XProtect: Apple'ın uygulama güvenilirliği ve yerleşik
  zararlı yazılım koruması.
- Santa: program çalıştırmalarını Endpoint Security ile kaydeder. Bu kişisel Mac
  için `config/Santa-Standalone.mobileconfig` profili artık sessiz **Monitor**
  modunu kullanır: bilinmeyen programlarda sürekli onay istemez, olayları kaydeder
  ve bozuk imzaları engeller. Gatekeeper, XProtect, ClamAV ve davranış korumaları
  aktif kalmalıdır.
- BlockBlock: LaunchAgent ve benzeri kalıcılık değişikliklerini engeller. Santa
  etkin olduğunda BlockBlock'un ek Notarization/Script yürütme engelleri aynı
  işi iki kez yapmaması için kapalı tutulmalıdır.
- RansomWhere?: hızlı toplu şifreleme davranışını durdurur.
- LuLu: uygulamaların dışarıya bağlantılarını denetler.
- VirusTotal: görünmez arka plan servisi önce yalnız SHA-256 sorgular. Normal
  indirilen veya karantinaya alınan bilinmeyen dosyaların içeriği otomatik
  yüklenmez. Dosya yükleme yalnız açık onayla ya da kişisel config dosyasından
  etkinleştirilen karantina otomatik analiziyle yapılır. İki motor aynı dosyayı
  eşzamanlı taşımaz.

ClamAV içerik taraması ve ortak karantinanın sahibidir; VirusTotal ikinci görüş,
Santa çalıştırma görünürlüğü, BlockBlock kalıcılık, RansomWhere? toplu şifreleme
ve LuLu dış ağ bağlantısı katmanıdır. Bu görev ayrımı çakışan uyarıları azaltır.

Doğrulanmış resmî Santa, BlockBlock ve RansomWhere kurucuları
`~/Downloads/Mac Security Installers` klasöründe tutulur. Hash ve geliştirici
imza kaydı `config/verified-installers.txt` dosyasındadır.

## Kurulum ve yönetim

ClamAV Homebrew ile kurulu ve imza veritabanı indirilmiş olmalıdır. Ardından:

```sh
./install.sh install
./install.sh status
./install.sh scan-now
./install.sh update-now
./install.sh uninstall
```

`uninstall` çalışan görevleri ve Finder hızlı eylemini kaldırır; karantina,
ayarlar ve günlükler veri kaybını önlemek için korunur.

İlk birleşik kurulum başarılı olduktan sonra eski `VirusTotal İzleyici.app` ve
LaunchAgent dosyası silinmez. Tarihli, `0700` izinli
`~/Library/Application Support/ClamAV-Automation/Migration Backups/` klasörüne
taşınır. Eski sonuç geçmişi yeni merkezi JSONL biçimine aktarılır; API anahtarı
uyumluluk ve gizlilik için `~/.config/vt-download-watcher/.env` konumunda kalır.

## Ayarlar ve kayıtlar

- Günlük tam tarama yolları:
  `~/Library/Application Support/ClamAV-Automation/scan-paths`
- Canlı izleme yolları:
  `~/Library/Application Support/ClamAV-Automation/realtime-paths`
- Karantina:
  `~/Library/Application Support/ClamAV-Automation/Quarantine/`
- Canlı durum:
  `~/Library/Application Support/ClamAV-Automation/realtime-status.json`
- Canlı olaylar:
  `~/Library/Logs/ClamAV-Automation/realtime-events.jsonl`
- VirusTotal durumu:
  `~/Library/Application Support/ClamAV-Automation/virustotal-status.json`
- VirusTotal sonuçları:
  `~/Library/Logs/ClamAV-Automation/virustotal-results.jsonl`
- Devam eden taramanın yüzde, dosya sayısı ve kalan süre durumu:
  `~/Library/Application Support/ClamAV-Automation/scan-progress.json`
- Karantina VirusTotal tekrar-engelleme durumu:
  `~/Library/Application Support/ClamAV-Automation/virustotal-quarantine-state.json`
- VirusTotal gizlilik ve yükleme politikası:
  `~/.config/vt-download-watcher/config.json`
- Ortak karantina koordinasyon kilidi:
  `~/Library/Application Support/ClamAV-Automation/coordination/quarantine.lock`
- Diğer günlükler: `~/Library/Logs/ClamAV-Automation/`

Yol dosyalarında her satıra mutlak bir yol veya `$HOME` ile başlayan bir yol
yazılabilir. Değişiklikten sonra canlı görev yeniden başlatılmalıdır. Koruma
klasörleri `0700`, hassas ayar, durum, olay ve karantina dosyaları `0600`
izinleriyle tutulur.

Uzun taramalar başlamadan önce erişilebilir dosyalar tek bir özel manifestte
sayılır. APFS firmlink'leri aynı klasörü ikinci kez gösterse bile aygıt/inode
kimliğiyle yalnız bir kez taranır. `/` seçildiğinde salt-okunur `/System` ve
bağlı disklerin `/Volumes` görünümü atlanır; bağlı bir diski tam taramak için
onu ayrıca **Dosya veya Klasör Tara** üzerinden seçmek gerekir. `.git`,
`node_modules`, sanal Python ortamları ve kullanıcı önbellekleri de varsayılan
olarak atlanır; yeni dosyalar canlı koruma tarafından ayrıca izlenir.
