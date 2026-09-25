#!/usr/bin/env bash
# ==========================================================================
#  ÜSTAD OSINT — Kali Linux başlatıcı (WSL veya gerçek Kali)
#  nmap varsa otomatik onu kullanır, yoksa yerleşik soket motoruna düşer.
# ==========================================================================
set -u
cd "$(dirname "$0")" || exit 1

echo "======================================================================"
echo "  ÜSTAD OSINT v1.0  ·  Saldırı Yüzeyi & Blue Team SOC Konsolu (Kali)"
echo "======================================================================"

if ! command -v python3 >/dev/null 2>&1; then
  echo "[HATA] python3 bulunamadı. Kur:  sudo apt update && sudo apt install -y python3"
  exit 1
fi

if command -v nmap >/dev/null 2>&1; then
  echo "[OK] nmap: $(nmap --version | head -1)"
else
  echo "[!] nmap yok — yerleşik soket motoru kullanılacak."
  echo "    Kurmak için:  sudo apt update && sudo apt install -y nmap"
fi

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[ -z "$IP" ] && IP="127.0.0.1"

echo
echo "  Kali konsolu   : http://127.0.0.1:8787"
echo "  Ağdaki diğer PC: http://$IP:8787   (--disari-ac ile)"
echo
echo "  Kapsam hatırlatması: yalnız KENDİ sistemlerin veya YAZILI İZİN"
echo "  aldığın sistemler. İzinsiz tarama TCK 243/244 kapsamında suçtur."
echo

if [ "${1:-}" = "--ag" ]; then
  exec python3 ustad-osint.py --port 8787 --disari-ac
else
  exec python3 ustad-osint.py --port 8787
fi
