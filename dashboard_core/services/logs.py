import csv
from datetime import datetime
from pathlib import Path
from dashboard_core import config
import functools

def log_action(category, action, result="success", user="-", target="-", detail="-"):
    log_file = Path(config.APP_LOG_DIR/f"{datetime.now():%Y-%m-%d}.csv")
    log_file.parent.mkdir(parents=True, exist_ok=True)
    is_new = not log_file.exists()
    with open(log_file, "a", newline="") as f:
        writer = csv.writer(f)
        if is_new:
            writer.writerow(["timestamp", "category", "user", "action", "target", "result", "detail"])
        writer.writerow([datetime.now().isoformat(), category, user, action, target, result, detail])


def logged(category, action):
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                response = await func(*args, **kwargs)
                is_failure = getattr(response, "status_code", 200) >= 400
                log_action(category=category, action=action,
                           result="failed" if is_failure else "success")
                return response
            except Exception as e:
                log_action(category=category, action=action, result="failed", detail=str(e))
                raise
        return wrapper
    return decorator