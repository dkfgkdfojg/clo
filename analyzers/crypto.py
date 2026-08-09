# analyzers/crypto.py
"""Пробив крипто-адреса (BTC/ETH и др.) через публичные обозреватели без ключа.

BTC — blockchain.info, ETH — blockchair. Для TRX/SOL даём ссылки на обозреватель.
Показывает баланс, число транзакций, суммарный оборот и даёт ссылку на explorer.
"""

from __future__ import annotations

from core.http import get_session, safe_get
from core.utils import dual_print, print_section, print_field, print_summary, logger
from core.validator import validate_crypto_address

EXPLORERS = {
    "btc": "https://www.blockchain.com/explorer/addresses/btc/{}",
    "eth": "https://etherscan.io/address/{}",
    "trx": "https://tronscan.org/#/address/{}",
    "sol": "https://solscan.io/account/{}",
}


def _btc(session, addr, results):
    r = safe_get(session, f"https://blockchain.info/rawaddr/{addr}?limit=0", timeout=15)
    if r.status_code != 200:
        dual_print(f"  [!] blockchain.info: {r.status_code}")
        return
    d = r.json()
    btc = 1e-8
    print_field("Баланс", f"{d.get('final_balance', 0) * btc:.8f} BTC")
    print_field("Транзакций", d.get("n_tx"))
    print_field("Получено всего", f"{d.get('total_received', 0) * btc:.8f} BTC")
    print_field("Отправлено всего", f"{d.get('total_sent', 0) * btc:.8f} BTC")
    results["Баланс"] = f"{d.get('final_balance', 0) * btc:.8f} BTC"
    results["Транзакций"] = str(d.get("n_tx", 0))


def _eth(session, addr, results):
    r = safe_get(
        session,
        f"https://api.blockchair.com/ethereum/dashboards/address/{addr}",
        timeout=15,
    )
    if r.status_code != 200:
        dual_print(f"  [!] blockchair: {r.status_code}")
        return
    data = (r.json().get("data") or {}).get(addr.lower(), {})
    addr_info = data.get("address", {})
    if not addr_info:
        dual_print("  [–] Адрес без активности или не найден.")
        return
    wei = 1e-18
    bal = float(addr_info.get("balance") or 0) * wei
    print_field("Баланс", f"{bal:.6f} ETH")
    print_field("Транзакций", addr_info.get("transaction_count"))
    print_field("Получено (ETH)", f"{float(addr_info.get('received') or 0) * wei:.6f}")
    print_field("Первая транзакция", addr_info.get("first_seen_receiving"))
    print_field("Последняя транзакция", addr_info.get("last_seen_spending")
                or addr_info.get("last_seen_receiving"))
    results["Баланс"] = f"{bal:.6f} ETH"
    results["Транзакций"] = str(addr_info.get("transaction_count", 0))


def analyze_crypto(target: str) -> None:
    addr = target.strip()
    kind = validate_crypto_address(addr)
    dual_print(f"\n{'═' * 58}")
    dual_print(f"  [+] КРИПТО-АДРЕС: {addr}  ({kind or 'неизвестный формат'})")
    dual_print(f"{'═' * 58}")

    if not kind:
        dual_print("  [!] Не похоже на BTC/ETH/TRX/SOL адрес.")
        return

    results: dict[str, str] = {}
    session = get_session()

    explorer = EXPLORERS.get(kind, "").format(addr)
    if explorer:
        print_field("Обозреватель", explorer)
        results["Обозреватель"] = explorer

    print_section(f"Данные сети ({kind.upper()})")
    try:
        if kind == "btc":
            _btc(session, addr, results)
        elif kind == "eth":
            _eth(session, addr, results)
        else:
            dual_print("  [i] Для этой сети — только ссылка на обозреватель выше.")
    except Exception as e:
        logger.debug("crypto %s: %s", kind, e)
        dual_print(f"  [!] Ошибка сети: {e}")

    print_summary(results, f"Крипто {addr[:12]}…")


if __name__ == "__main__":
    import sys
    analyze_crypto(sys.argv[1] if len(sys.argv) > 1
                   else "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
