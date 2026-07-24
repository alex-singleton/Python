#!/usr/bin/env python3
"""
VPN Firewall - Əsas başlanğıc skripti.
Bu skripti root hüquqları ilə işə salın (iptables üçün lazımdır).

İstifadə:
    sudo python3 run.py
    sudo python3 run.py --port 8080
    sudo python3 run.py --host 0.0.0.0 --port 9450
"""
import argparse
import logging
import os
import sys
import signal

# Layihə qovluğunu path-a əlavə et
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def setup_logging():
    """Logging konfiqurasiyası."""
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
    os.makedirs(log_dir, exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(os.path.join(log_dir, "firewall.log")),
            logging.StreamHandler(sys.stdout),
        ],
    )


def check_root():
    """Root hüquqlarını yoxla."""
    if os.geteuid() != 0:
        print("=" * 60)
        print("  XƏBƏRDARLIQ: Bu proqram root hüquqları tələb edir!")
        print("  iptables qaydalarını idarə etmək üçün sudo istifadə edin.")
        print("")
        print("  İstifadə: sudo python3 run.py")
        print("=" * 60)
        print("")
        print("Veb panel root-suz da işləyə bilər, lakin")
        print("firewall qaydaları tətbiq olunmayacaq.")
        print("")
        response = input("Root-suz davam etmək istəyirsiniz? (y/N): ")
        if response.lower() != "y":
            sys.exit(1)


def setup_firewall():
    """Firewall engine-i qur."""
    from app.firewall_engine import engine

    logger = logging.getLogger("firewall.setup")

    if os.geteuid() == 0:
        logger.info("Firewall chain-ləri qurulur...")
        engine.setup_chains()
        logger.info("Mövcud qaydalar sinxronlaşdırılır...")
        engine.sync_all_rules()
        logger.info("Firewall engine hazırdır!")
    else:
        logger.warning("Root hüquqları yoxdur - iptables qaydaları tətbiq edilməyəcək")


def setup_socks_server():
    """SOCKS5 proxy serveri başlat."""
    from app.socks_server import socks_server

    logger = logging.getLogger("firewall.setup")
    socks_server.start()
    logger.info("SOCKS5 proxy server port 1080-də başladıldı")


def cleanup(signum, frame):
    """Proqram bağlananda təmizlik."""
    logger = logging.getLogger("firewall.cleanup")
    logger.info("Proqram bağlanır...")

    if os.geteuid() == 0:
        from app.firewall_engine import engine
        logger.info("Firewall chain-ləri təmizlənir...")
        engine.cleanup_chains()

    logger.info("Proqram bağlandı.")
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description="VPN Firewall Panel")
    parser.add_argument("--host", default="0.0.0.0", help="Dinləmə ünvanı (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=9450, help="Port nömrəsi (default: 9450)")
    parser.add_argument("--debug", action="store_true", help="Debug rejimi")
    parser.add_argument("--no-engine", action="store_true", help="Firewall engine-i işə salma")
    args = parser.parse_args()

    setup_logging()
    logger = logging.getLogger("firewall.main")

    print("")
    print("╔══════════════════════════════════════════════╗")
    print("║          VPN FIREWALL PANEL v1.0            ║")
    print("╠══════════════════════════════════════════════╣")
    print("║  Domain Bloklama (HTTP + HTTPS)             ║")
    print("║  IP Bloklama (iptables)                     ║")
    print("║  Whitelist İdarəetmə                       ║")
    print("╚══════════════════════════════════════════════╝")
    print("")

    # Root yoxlaması
    check_root()

    # Signal handler (təmiz bağlanma üçün)
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    # Firewall engine qur
    if not args.no_engine:
        setup_firewall()
    else:
        logger.info("Firewall engine deaktivdir (--no-engine)")

    # SOCKS5 proxy server başlat
    setup_socks_server()

    # Flask app yarat və işə sal
    from app import create_app
    app = create_app()

    logger.info(f"Veb panel başladılır: http://{args.host}:{args.port}")
    logger.info("Default giriş: admin / admin123")
    print(f"\n  Panel: http://{args.host}:{args.port}")
    print(f"  Giriş: admin / admin123\n")

    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
