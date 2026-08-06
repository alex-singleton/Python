#!/usr/bin/env python3
"""
VPN Firewall - Main startup script.
Run this script with root privileges (required for iptables).

Usage:
    sudo python3 run.py
    sudo python3 run.py --port 8080
    sudo python3 run.py --host 0.0.0.0 --port 9450
"""
import argparse
import logging
import os
import sys
import signal

# Add project directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def setup_logging():
    """Configure logging."""
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
    """Check root privileges."""
    if os.geteuid() != 0:
        print("=" * 60)
        print("  WARNING: This program requires root privileges!")
        print("  Use sudo to manage iptables rules.")
        print("")
        print("  Usage: sudo python3 run.py")
        print("=" * 60)
        print("")
        print("The web panel can run without root, but")
        print("firewall rules will not be applied.")
        print("")
        response = input("Continue without root? (y/N): ")
        if response.lower() != "y":
            sys.exit(1)


def setup_firewall():
    """Set up firewall engine."""
    from app.firewall_engine import engine

    logger = logging.getLogger("firewall.setup")

    if os.geteuid() == 0:
        logger.info("Setting up firewall chains...")
        engine.setup_chains()
        logger.info("Synchronizing existing rules...")
        engine.sync_all_rules()
        logger.info("Firewall engine ready!")
    else:
        logger.warning("No root privileges - iptables rules will not be applied")


def setup_socks_server():
    """Start SOCKS5 proxy server."""
    from app.socks_server import socks_server

    logger = logging.getLogger("firewall.setup")
    socks_server.start()
    logger.info("SOCKS5 proxy server started on port 1080")


def cleanup(signum, frame):
    """Cleanup on program exit."""
    logger = logging.getLogger("firewall.cleanup")
    logger.info("Shutting down...")

    if os.geteuid() == 0:
        from app.firewall_engine import engine
        logger.info("Cleaning up firewall chains...")
        engine.cleanup_chains()

    logger.info("Shutdown complete.")
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description="VPN Firewall Panel")
    parser.add_argument("--host", default="0.0.0.0", help="Listen address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=9450, help="Port number (default: 9450)")
    parser.add_argument("--debug", action="store_true", help="Debug mode")
    parser.add_argument("--no-engine", action="store_true", help="Don't start firewall engine")
    args = parser.parse_args()

    setup_logging()
    logger = logging.getLogger("firewall.main")

    print("")
    print("+" + "=" * 46 + "+")
    print("|          VPN FIREWALL PANEL v1.0            |")
    print("|" + "=" * 46 + "|")
    print("|  Domain Blocking (HTTP + HTTPS)             |")
    print("|  IP Blocking (iptables)                     |")
    print("|  Whitelist Management                       |")
    print("+" + "=" * 46 + "+")
    print("")

    # Root check
    check_root()

    # Signal handler (for clean shutdown)
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    # Set up firewall engine
    if not args.no_engine:
        setup_firewall()
    else:
        logger.info("Firewall engine disabled (--no-engine)")

    # Start SOCKS5 proxy server
    setup_socks_server()

    # Create and run Flask app
    from app import create_app
    app = create_app()

    logger.info(f"Web panel starting: http://{args.host}:{args.port}")
    logger.info("Default login: admin / admin123")
    print(f"\n  Panel: http://{args.host}:{args.port}")
    print(f"  Login: admin / admin123\n")

    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
