"""Offscreen functional check: SentinelPet starts and reacts to real statebus events."""
import os, sys, time
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QApplication
from sentinel import statebus
from overlay.sentinel_pet import SentinelPet

app = QApplication(sys.argv)
statebus.clear()  # stale verdicts from previous runs must not pre-trigger notifications
pet = SentinelPet(draggable=True)
pet.show()

flags = pet.windowFlags()
assert flags & Qt.FramelessWindowHint, "not frameless"
assert flags & Qt.WindowStaysOnTopHint, "not always-on-top"
assert pet.testAttribute(Qt.WA_TranslucentBackground), "not translucent"
print("[ok] window: frameless, always-on-top, translucent")

# Phase 1: real backend state -> investigating
statebus.publish(state="investigating", risk=0, verdict=None,
                 current_tool="parse_headers", message="Analyzing phishing.eml")
t0 = time.time()
while pet.state != "investigating" and time.time() - t0 < 3:
    app.processEvents(); time.sleep(0.05)
assert pet.state == "investigating", f"pet did not react: {pet.state}"
assert pet.current_tool == "parse_headers"
assert "phishing.eml" in pet.bubble
print(f"[ok] SCANNING reaction: state={pet.state} tool={pet.current_tool} bubble='{pet.bubble}'")

# Phase 2: tool running
statebus.publish(state="tool_running", risk=60, current_tool="extract_urls", message="extracting urls")
t0 = time.time()
while pet.risk != 60 and time.time() - t0 < 3:
    app.processEvents(); time.sleep(0.05)
assert pet.risk == 60 and pet.current_tool == "extract_urls"
print("[ok] PROGRESS reaction: risk=60 tool=extract_urls")

# Phase 3: verdict
statebus.publish(state="verdict", risk=100, verdict="MALICIOUS", message="verdict: MALICIOUS (100%)")
t0 = time.time()
while pet.verdict != "MALICIOUS" and time.time() - t0 < 3:
    app.processEvents(); time.sleep(0.05)
assert pet.verdict == "MALICIOUS", f"verdict not received: {pet.verdict}"
assert pet._last_notified_verdict == "MALICIOUS", "verdict notification not triggered"
print("[ok] VERDICT reaction: verdict=MALICIOUS, notification fired")

print("ALL COMPANION CHECKS PASSED")
