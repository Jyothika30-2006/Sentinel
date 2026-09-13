"""Unit tests for SentinelPet Event-Driven State Machine & Reaction Timers."""
from __future__ import annotations

import sys
from pathlib import Path

# Ensure repo root is importable
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest
from PySide6.QtWidgets import QApplication

# Create single QApplication instance for PySide6 GUI tests
@pytest.fixture(scope="session", autouse=True)
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    yield app


def test_sentinel_pet_state_machine(tmp_path):
    from overlay.sentinel_pet import SentinelPet

    state_file = tmp_path / "test_state.json"
    state_file.write_text('{"state": "idle", "risk": 0}', encoding="utf-8")

    pet = SentinelPet(state_path=str(state_file), draggable=True)

    # 1. Initial State -> IDLE, stable, timer inactive (0 CPU)
    assert pet._machine_state == "IDLE"
    assert pet._is_reacting is False
    assert pet._wobble == 0.0
    assert pet.anim.isActive() is False

    # 2. Transition to SCANNING -> Timer active for cyan laser beam
    pet.set_state("SCANNING", {"message": "Investigating clean.eml..."})
    assert pet._machine_state == "SCANNING"
    assert pet.anim.isActive() is True

    # 3. Transition to SUSPICIOUS -> Finite 1.8s reaction, wobble=1.0
    pet.set_state("SUSPICIOUS", {"risk": 75, "verdict": "SUSPICIOUS", "message": "Phishing attempt"})
    assert pet._machine_state == "SUSPICIOUS"
    assert pet._is_reacting is True
    assert pet._wobble == 1.0
    assert pet._reaction_timer is not None
    assert pet.anim.isActive() is True

    # 4. Reaction finishes -> Settles into STABLE IDLE state (0 wobble, 0 CPU)
    pet._on_reaction_finished()
    assert pet._machine_state == "IDLE"
    assert pet.state == "idle"
    assert pet._is_reacting is False
    assert pet._wobble == 0.0
    assert pet._reaction_timer is None
    assert pet.anim.isActive() is False  # Frame timer stopped when settled!

    # 5. Transition to SAFE -> Brief reaction then settle
    pet.set_state("SAFE", {"risk": 0, "verdict": "SAFE", "message": "Clean email"})
    assert pet._machine_state == "SAFE"
    assert pet._is_reacting is True
    pet._on_reaction_finished()
    assert pet._machine_state == "IDLE"
    assert pet.anim.isActive() is False

    # 6. Transition to LOCKED -> Sleeping/locked state
    pet.set_state("LOCKED")
    assert pet._machine_state == "LOCKED"
    assert pet.anim.isActive() is False

    # Clean up widget
    pet.close()
