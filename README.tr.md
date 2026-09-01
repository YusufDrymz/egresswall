# egresswall

**Türkçe** · [English](README.md)

Bir sunucu birkaç yerle konuşur: paket depoları, veritabanı, API sağlayıcıları.
Ele geçirilmiş bir bağımlılık bir yerle daha konuşur. `egresswall`, sıradan Linux
sunucuları için önce öğrenen sonra uygulayan bir giden-trafik firewall'udur:
`learn` modunda bir gün çalıştırın, makinenin gerçekten nereye bağlandığını IP
yerine domain ve port olarak yazsın. `enforce` moduna geçin, listede olmayan her
şey düşürülsün ve loglansın; çalınmış bir token'ın ilk dışarı çıkışı dahil.

> **Durum: erken.** `learn`, `check` ve `enforce` çalışıyor; üçü de CI'da
> gerçek bir Linux runner'da uçtan uca deneniyor. Henüz hiçbir yerde
> production'da değil, süreç bazlı kurallar yol haritasında.

## Neden

2025'teki npm solucan dalgası ve ondan önceki her tedarik zinciri olayı aynı
senaryoyu izledi: build ya da uygulama süreci zehirli bir paket çeker, paket
bulabildiği kimlik bilgilerini okur ve bir yere POST'lar. Bu adımların her birini
önlemek zor. Sonuncusunu fark etmek kolay, yeter ki makinenin nereyle konuşması
gerektiğinin bir listesi olsun ve gerisini reddetsin.

Kubernetes bunu Cilium veya Calico'dan alıyor. GitHub Actions Harden-Runner'dan.
Masaüstü OpenSnitch veya Little Snitch'ten. Uygulamanızı çalıştıran bir VPS,
Docker host'u ya da bare-metal makine ise gelen trafik odaklı `ufw` ile ya da
kimsenin elle bakmak istemediği nftables kurallarıyla kalıyor. Proje tamamen o
boşluk için.

## Nasıl çalışıyor

```
$ sudo egresswall learn -out egresswall.yaml       # bir gün izle
$ egresswall check registry.npmjs.org:443          # policy'ye sor, offline
$ sudo egresswall enforce -policy egresswall.yaml  # gerisini reddet, logla
```

`learn` her arayüzde tek bir raw socket (AF_PACKET, cooked mod) açar ve iki şey
okur: adres→isim haritasını kuran DNS cevapları ve her giden akışın ilk paketi.
Yönü kernel işaretler (PACKET_OUTGOING), adresten tahmin yok. TCP akışı SYN'de
sayılır; UDP'de tuple'ın ilk paketini kim attıysa başlatan odur, böylece bizim
gelen trafiğe verdiğimiz cevaplar hedef olarak görünmez. conntrack yok, nftables
yok, kernel modülü yok. Örnek çıktı için İngilizce README.

- **IP değil domain.** Policy `*.pypi.org` der; daemon host üstündeki DNS
  cevaplarını izler, o isimlerin çözüldüğü IP'leri TTL ile süren dolan bir
  nftables set'inde tutar. İzinli hiçbir ismin çözülmediği bir IP'ye bağlantı
  reddedilir; sızdırma uç noktalarının neredeyse hepsi bu durumdadır.
- **Önce deny, sonra dosya sırasıyla allow, sonra default.** Geniş bir 443
  kuralı olsa da `169.254.169.254` metadata servisi kapalı kalır.
- **Tek binary, ajan yok, bulut yok.** Policy deployment'ın yanında commit'lenen
  bir YAML dosyası. Retler isim, IP, port ve kural adıyla loga düşer.

### enforce

`enforce` tek bir nftables tablosu (`inet egresswall`) yükler: bir output
chain, her domain kuralı ve adres ailesi için bir timeout'lu set. `learn`'deki
raw socket açık kalır; bir kuralın kapsadığı isim için gelen her DNS cevabı,
adresleri o kuralın set'ine TTL süresince (en az beş dakika) yazar. Başlangıçta
policy'deki tam isimler bir kez çözülür ki adresi önbelleğinde tutan süreçler
reddedilmesin; wildcard'lar seed edilemez.

Reddedilen paket sessizce düşürülmez, ICMP "administratively prohibited" ile
reddedilir: süreç timeout beklemek yerine milisaniyeler içinde net bir hatayla
düşer. Her ret kernel log'una hangi kuralın sebep olduğuyla düşer; daemon bunu
`/dev/kmsg`'den okuyup DNS ismiyle ekrana yazar.

Bilinmesi gerekenler:

- `-dry-run` hiçbir şeye dokunmaz, sadece neyin reddedileceğini yazar. Önce
  onu çalıştırın.
- `-print` policy'nin dönüştüğü nft ruleset'ini gösterir. Okuyun.
- Daemon temiz durdurulunca tablo kaldırılır; DNS beslemesi olmayan bir
  firewall dakikalar içinde her şeyi reddederdi. Daemon çökerse tablo kalır
  ve reddetmeye devam eder; `enforce -off` kaldırır.
- Gelen trafiğe dokunulmaz, SSH oturumları yaşar; kurulu bağlantılar
  kontrolsüz kabul edilir.
- Sadece host'un kendi output chain'i filtrelenir; container trafiği forward
  yolundan geçer ve henüz kapsanmıyor.

## Policy

Örnek ve kurallar için [examples/egresswall.yaml](examples/egresswall.yaml).
Bir kural, hedef domain'lerinden **veya** CIDR'larından birine denk gelince ve
port ile protokol uyunca eşleşir. Domain'i de CIDR'ı da olmayan kural her host'a
uyar; DNS'i resolver neredeyse oraya açmanın yolu bu. `*.example.com` sadece alt
alanları kapsar, apex'i kastediyorsanız `example.com`'u da yazın. Dosyadaki
bilinmeyen anahtar hata, sessiz geçilmez.

```
$ egresswall check -policy examples/egresswall.yaml registry.npmjs.org:443
allow  registry.npmjs.org:443  domain registry.npmjs.org  (rule package-registries)
```

`check` allow'da 0, deny'da 1 ile çıkar; shell koşulunda ve CI'da kullanılır.

## Yakalamayacakları

- **İzinli bir host üzerinden DoH/DoT.** `dns.google` listedeyse süreç her şeyi
  oradan çözüp IP ile bağlanır. İzin vermeyin.
- **Keyfi veri saklayan izinli host'lar.** `*.githubusercontent.com` ya da bir
  S3 endpoint'i izinliyse saldırgan oradan sızdırır. Kuralları dar tutun.
- **Paylaşımlı CDN adresleri.** İzinli bir isimle düşman bir isim aynı edge
  IP'ye çözülebilir. Bu, DNS güdümlü her allowlist'in bilinen zayıflığı ve
  süreç bazlı kuralların yol haritasında olma sebebi.

## Yol haritası

- Docker: forward yolunu da filtrele, host'taki container'lar aynı policy'yi alsın.
- Süreç / cgroup bazlı kurallar.
- Alarm hedefleri: önce journald, sonra webhook.

## Lisans

MIT
