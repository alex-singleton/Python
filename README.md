# VPN Firewall Panel

Python əsaslı VPN firewall sistemi. Domain bloklama (HTTPS daxil), IP bloklama, whitelist idarəetmə və veb admin paneli.

## Xüsusiyyətlər

- **Domain Bloklama** - HTTP + HTTPS (TLS SNI string match) + DNS sorğuları
- **IP Bloklama** - iptables ilə ingress/egress bloklama, CIDR dəstəyi
- **Whitelist** - İcazə verilən domain/IP siyahısı (blok qaydalarından üstün)
- **Veb Panel** - Bootstrap 5 əsaslı responsive admin interfeysi
- **Admin Login** - Parol dəyişmə, session idarəetmə
- **Subdomain Dəstəyi** - `example.com` bloklananda `sub.example.com` da bloklanır
- **Fayl Yükləmə** - TXT fayllardan toplu import
- **Systemd Service** - Avtomatik başlanğıc və dayanma

## Tələblər

- Linux (Ubuntu/Debian tövsiyə olunur)
- Python 3.8+
- iptables
- Root hüquqları (iptables üçün)

## Sürətli Quraşdırma

```bash
# Reponu klonla
git clone <repo-url> /opt/firewall
cd /opt/firewall

# Avtomatik quraşdırma
sudo bash install.sh
```

## Əl ilə Quraşdırma

```bash
# Lazımi paketlər
sudo apt install python3 python3-pip python3-venv iptables

# Virtual mühit
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Data qovluqları
mkdir -p data logs

# İşə sal
sudo python3 run.py
```

## İstifadə

### Başlatma

```bash
# Standart (port 9450)
sudo python3 run.py

# Xüsusi port
sudo python3 run.py --port 8080

# Debug rejimi
sudo python3 run.py --debug

# Engine-siz (yalnız panel)
python3 run.py --no-engine
```

### Systemd ilə

```bash
sudo systemctl start firewall      # Başlat
sudo systemctl stop firewall       # Dayandır
sudo systemctl restart firewall    # Yenidən başlat
sudo systemctl status firewall     # Status
sudo journalctl -u firewall -f     # Loglar
```

### Veb Panel

Brauzer ilə `http://server-ip:9450` ünvanına daxil olun.

**Default giriş:**
- İstifadəçi: `admin`
- Parol: `admin123`

> İlk girişdən sonra parolu mütləq dəyişdirin!

## Bloklama Metodları

### Domain Bloklama (HTTPS daxil)

Üç səviyyədə bloklama:
1. **TLS SNI** - HTTPS trafikində Server Name Indication sahəsini yoxlayır (port 443)
2. **HTTP Host** - HTTP trafikində Host header-i yoxlayır (port 80)
3. **DNS** - Domain adına DNS sorğularını bloklayır (port 53)

### IP Bloklama

- iptables `DROP` qaydası ilə həm gələn, həm gedən trafik bloklanır
- CIDR notation dəstəklənir (məs: `192.168.1.0/24`)

### Whitelist

- Whitelist-ə əlavə edilən elementlər avtomatik blok siyahısından silinir
- Whitelist qaydaları `ACCEPT` olaraq chain-in əvvəlinə əlavə edilir
- Blok qaydalarından prioritetlidir

## Layihə Strukturu

```
Firewall/
├── run.py                  # Əsas başlanğıc skripti
├── config.py               # Konfiqurasiya
├── requirements.txt        # Python paketləri
├── install.sh              # Quraşdırma skripti
├── firewall.service        # Systemd service faylı
├── app/
│   ├── __init__.py         # Flask app factory
│   ├── models.py           # Admin model
│   ├── firewall_core.py    # Bloklama məntiqi
│   ├── firewall_engine.py  # iptables inteqrasiyası
│   ├── routes/
│   │   ├── auth.py         # Login/logout
│   │   ├── dashboard.py    # Panel səhifəsi
│   │   ├── domains.py      # Domain bloklama
│   │   ├── ips.py          # IP bloklama
│   │   └── whitelist.py    # Whitelist
│   ├── templates/          # HTML şablonlar
│   └── static/css/         # CSS
├── data/                   # Blok siyahıları
│   ├── blocked_domains.txt
│   ├── blocked_ips.txt
│   ├── whitelist.txt
│   └── admin.json
└── logs/                   # Log faylları
    └── firewall.log
```

## API İstifadə Nümunələri

### Blok Siyahısı Fayl Formatı

```text
# Bloklanacaq domainlər (hər sətirdə bir domain)
# Bu şərh sətridir - keçilir
example.com
malware-site.net
tracking.io
ads.network.com
```

### IP Siyahısı Fayl Formatı

```text
# Bloklanacaq IP-lər
192.168.1.100
10.0.0.50
172.16.0.0/16
# Botnet IP-ləri
203.0.113.0/24
```

## Təhlükəsizlik Qeydləri

- Default parolu mütləq dəyişdirin
- `FIREWALL_SECRET_KEY` mühit dəyişənini təyin edin
- Panelə yalnız etibarlı şəbəkələrdən giriş verin
- Mümkünsə HTTPS (nginx reverse proxy) arxasında işlədin
- Mütəmadi olaraq logları yoxlayın

## Mühit Dəyişənləri

| Dəyişən | Təsvir | Default |
|---------|--------|---------|
| `FIREWALL_SECRET_KEY` | Flask secret key | `change-this-secret-key-in-production` |
| `FIREWALL_DEBUG` | Debug rejimi | `False` |
| `FIREWALL_INTERFACE` | VPN interfeysi | `tun0` |
| `FIREWALL_WEB_PORT` | Veb panel portu | `9450` |
| `FIREWALL_ADMIN_USER` | Admin istifadəçi adı | `admin` |

## Lisenziya

MIT License
