import logging
import platform
import warnings

logger = logging.getLogger("logs.notifier")


def send_notification(title: str, message: str, duration: int = 5, icon_path: str = None) -> bool:
    if platform.system() != "Windows":
        logger.debug("Skipping Windows notification on non-Windows platform")
        return False

    try:
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", message="pkg_resources is deprecated.*")
            from win10toast import ToastNotifier

        toaster = ToastNotifier()
        toaster.show_toast(
            title,
            message,
            icon_path=icon_path,
            duration=duration,
            threaded=True,
        )
        return True
    except Exception as exc:
        logger.warning(f"Could not show Windows notification: {exc}")
        return False


def send_monitor_alert_notification(alert: dict) -> bool:
    severity = alert.get("severity") or "Unknown"
    attack_type = alert.get("attack_type") or "Network anomaly"
    score = alert.get("score")
    targeted_ports = alert.get("targeted_ports") or []

    port_text = ""
    if targeted_ports:
        ports = ", ".join(str(item.get("port")) for item in targeted_ports[:3] if item.get("port") is not None)
        if ports:
            port_text = f" Ports: {ports}."

    score_text = f" Score: {score}." if score is not None else ""
    return send_notification(
        title=f"L.O.G.S. Monitor Alert: {severity}",
        message=f"{attack_type}.{score_text}{port_text}",
        duration=8,
    )
