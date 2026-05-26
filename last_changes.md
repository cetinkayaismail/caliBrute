# Son Değişiklikler (Last Changes)

CaliBrute projesinde yapılan son geliştirmeler ve hata düzeltmeleri aşağıda özetlenmiştir:

### 1. IP Spoofing Hata Düzeltmesi (`pkg/utils/utils.go`)
- `GenerateSpoofedIP` fonksiyonunda IP adresini geçersiz karakterlere dönüştüren byte-to-string mantık hatası giderildi.
- IP adresi standarda uygun şekilde `fmt.Sprintf` ile dotted-decimal IPv4 formatına dönüştürüldü.

### 2. HTTP Client & Transport Yeniden Kullanımı (`pkg/utils/utils.go` & `pkg/engine/engine.go`)
- Her istek için yeni bir HTTP istemcisi (client) oluşturmak yerine, `Engine` struct'ına ortak bir `Client` alanı eklenerek tek bir istemcinin tüm worker'lar tarafından kullanılması sağlandı. Bu sayede TCP bağlantı havuzundan yararlanıldı ve port tükenmesi (socket exhaustion) riski engellendi.
- Proxy rotasyon yapısı paylaşılan `http.Transport` nesnesi üzerinde dinamik hale getirildi. Her istekte yeni bir proxy adresi `transport.Proxy` callback fonksiyonu aracılığıyla döndürülmektedir.

### 3. Rate Limit / Engelleme Karşısında Otomatik Yeniden Deneme (`pkg/engine/engine.go`)
- `worker` fonksiyonundaki tekil istek mantığı maksimum 5 denemelik bir döngü ile sarmalandı.
- Bloklanma (`res.IsBlocked`) tespit edildiğinde ilgili kombinasyon atlanmak yerine 30 saniye beklenip tekrar denenmektedir.
- Bekleme süresi esnasında `stopChan` sinyali dinlenerek, başka bir worker başarılı giriş bilgisi bulduğunda uygulamanın gecikmeden temiz bir şekilde sonlanması sağlandı.

### 4. İstek Türüne Duyarlı Auto-Inject Parser (`pkg/parser/parser.go`)
- `autoInjectPlaceholders` fonksiyonu, istek başlığındaki `Content-Type` alanını denetleyecek şekilde geliştirildi.
- JSON gövdeleri ve Form / URL-encoded parametreleri için parametre sınırlarını (`&` ve `^` işaretlerini) koruyan daha kararlı regex kalıpları yazıldı.
- Boş bırakılmış parametrelerin (örneğin `username=&password=`) de başarıyla otomatik doldurulabilmesi sağlandı.

---
*Bu değişiklikler sonrasında proje başarıyla derlenmiştir.*
