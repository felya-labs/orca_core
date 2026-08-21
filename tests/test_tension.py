import os
import shutil
import time

import pytest


def test_tension_move_motors_false(connected_mock_hand):
    connected_mock_hand.tension(move_motors=False, blocking=False)
    assert connected_mock_hand._task_thread.is_alive()
    connected_mock_hand.stop_task()
    assert not connected_mock_hand._task_thread.is_alive()


def test_tension_move_motors_true(connected_mock_hand):
    connected_mock_hand.tension(move_motors=True, blocking=False)
    time.sleep(1)
    assert connected_mock_hand._task_thread.is_alive()
    connected_mock_hand.stop_task()
    time.sleep(0.1)
    assert not connected_mock_hand._task_thread.is_alive()


def test_tension_interrupt_after_3_seconds(connected_mock_hand):
    connected_mock_hand.tension(move_motors=True, blocking=False)
    time.sleep(3)
    assert connected_mock_hand._task_thread.is_alive(), "Tension task should still be running"
    connected_mock_hand.stop_task()
    time.sleep(0.1)
    assert not connected_mock_hand._task_thread.is_alive(), "Tension task should have stopped"


def test_second_tension_is_rejected(connected_mock_hand):
    connected_mock_hand.tension(move_motors=True, blocking=False)
    connected_mock_hand.tension(move_motors=True, blocking=False)
    assert connected_mock_hand._task_thread.is_alive()
    assert connected_mock_hand._current_task == "_tension"
    connected_mock_hand.stop_task()
    time.sleep(0.1)
    assert not connected_mock_hand._task_thread.is_alive()


def test_tension_emits_phase_events(connected_mock_hand):
    import threading

    events = []
    holding = threading.Event()

    def cb(event):
        events.append(event)
        if event.get("phase") == "holding":
            holding.set()

    thread = threading.Thread(
        target=lambda: connected_mock_hand.tension(
            blocking=True, progress_callback=cb
        )
    )
    thread.start()
    assert holding.wait(timeout=120), f"never reached holding: {events}"
    connected_mock_hand._task_stop_event.set()
    thread.join(timeout=10)
    assert not thread.is_alive()

    phases = [e["phase"] for e in events if e["event"] == "phase"]
    assert phases[0] == "winding"
    assert "ramp" in phases and "holding" in phases
    assert phases[-1] == "released"
    assert any(e["event"] == "winding_progress" for e in events)


def test_run_tension_exception_restores_hand_state(tmp_path):
    """An exception mid-winding must disable torque and restore the configured
    control mode and current limit, not leave the hand straining."""
    import orca_core
    from orca_core import MockOrcaHand
    from orca_core.maintenance.tensioning import run_tension
    from orca_core.utils import update_yaml

    model_config = os.path.join(
        os.path.dirname(orca_core.__file__),
        "models", "v2", "orcahand-right", "config.yaml",
    )
    config_path = tmp_path / "config.yaml"
    shutil.copy(model_config, config_path)
    update_yaml(str(config_path), "max_current", 250)
    update_yaml(str(config_path), "calibration_current", 200)
    update_yaml(str(config_path), "control_mode", "position")

    hand = MockOrcaHand(config_path=str(config_path))
    success, msg = hand.connect()
    assert success, msg
    try:
        def boom(*args, **kwargs):
            raise RuntimeError("bus died")

        hand.get_motor_pos = boom

        events = []
        with pytest.raises(RuntimeError, match="bus died"):
            run_tension(hand, move_motors=True, progress_callback=events.append)

        client = hand.motor_client
        assert not any(client._torque_enabled.values()), "torque left enabled"
        assert set(client._operating_mode.values()) == {3}, "control mode not restored"
        assert all(c == 250 for c in client._cur.values()), "current limit not restored"
        phases = [e["phase"] for e in events if e["event"] == "phase"]
        assert phases[-1] == "released"
    finally:
        del hand.get_motor_pos
        hand.disconnect()


def test_run_tension_holding_prints_nothing(connected_mock_hand, capsys):
    """Operator guidance is the CLI's job; the packaged routine must not print
    terminal-only instructions like the Ctrl+C hint."""
    from orca_core.maintenance.tensioning import run_tension

    capsys.readouterr()
    run_tension(connected_mock_hand, move_motors=False, should_stop=lambda: True)
    assert capsys.readouterr().out == ""


def test_run_tension_scopes_every_write_to_exact_selected_motors(
    connected_mock_hand, monkeypatch
):
    from orca_core.maintenance.tensioning import run_tension

    hand = connected_mock_hand
    selected = [
        hand.config.joint_to_motor_map["index_mcp"],
        hand.config.joint_to_motor_map["middle_mcp"],
    ]
    excluded = hand.config.joint_to_motor_map["pinky_pip"]
    client = hand.motor_client
    writes = []

    for method_name in (
        "set_torque_enabled",
        "set_operating_mode",
        "write_desired_current",
        "write_desired_pos",
    ):
        original = getattr(client, method_name)

        def traced(motor_ids, *args, _original=original, _name=method_name, **kwargs):
            writes.append((_name, tuple(motor_ids)))
            return _original(motor_ids, *args, **kwargs)

        monkeypatch.setattr(client, method_name, traced)

    run_tension(
        hand,
        move_motors=True,
        motor_ids=selected,
        winding_current=120,
        hold_current=100,
        max_wind_s=0.001,
        hold_duration_s=0.001,
    )

    assert writes
    assert any(method == "write_desired_pos" for method, _ in writes)
    assert all(set(motor_ids).issubset(selected) for _, motor_ids in writes), writes
    assert all(excluded not in motor_ids for _, motor_ids in writes)
    assert not any(client._torque_enabled.values())


@pytest.mark.parametrize(
    ("motor_ids", "match"),
    [
        ([], "nonempty"),
        ([2, 2], "unique"),
        ([999], "unknown"),
        ([True], "integers"),
    ],
)
def test_run_tension_rejects_invalid_scope_before_any_write(
    connected_mock_hand, monkeypatch, motor_ids, match
):
    from orca_core.maintenance.tensioning import run_tension

    writes = []
    client = connected_mock_hand.motor_client
    for method_name in (
        "set_torque_enabled",
        "set_operating_mode",
        "write_desired_current",
        "write_desired_pos",
    ):
        original = getattr(client, method_name)

        def traced(ids, *args, _original=original, _name=method_name, **kwargs):
            writes.append((_name, tuple(ids)))
            return _original(ids, *args, **kwargs)

        monkeypatch.setattr(client, method_name, traced)

    with pytest.raises(ValueError, match=match):
        run_tension(connected_mock_hand, motor_ids=motor_ids)
    assert writes == []


@pytest.mark.parametrize(
    "kwargs",
    [
        {"winding_current": 0},
        {"hold_current": float("nan")},
        {"max_wind_s": float("inf")},
        {"hold_duration_s": -1},
    ],
)
def test_run_tension_rejects_invalid_bounds_before_any_write(
    connected_mock_hand, monkeypatch, kwargs
):
    from orca_core.maintenance.tensioning import run_tension

    writes = []
    client = connected_mock_hand.motor_client
    original = client.set_operating_mode

    def traced(ids, *args, **call_kwargs):
        writes.append(tuple(ids))
        return original(ids, *args, **call_kwargs)

    monkeypatch.setattr(client, "set_operating_mode", traced)
    with pytest.raises(ValueError, match="positive finite"):
        run_tension(connected_mock_hand, motor_ids=[2], **kwargs)
    assert writes == []


def test_profiled_tension_uses_acknowledged_selected_motor_writes(
    connected_mock_hand, monkeypatch
):
    hand = connected_mock_hand
    selected = [hand.config.joint_to_motor_map["index_mcp"]]
    writes = []
    client = hand.motor_client
    monkeypatch.setattr(client, "supports_profiled_position_writes", True)

    def profiled(motor_ids, positions, *, speed, acceleration, torque):
        writes.append((tuple(motor_ids), speed, acceleration, torque))
        return []

    monkeypatch.setattr(client, "write_desired_pos_profiled", profiled)

    hand.tension(
        blocking=True,
        motor_ids=selected,
        winding_current=120,
        hold_current=100,
        max_wind_s=0.001,
        hold_duration_s=0.001,
        profile_speed=10,
        profile_acceleration=5,
        profile_torque=120,
    )

    assert writes
    assert all(item == ((selected[0],), 10, 5, 120) for item in writes)


def test_profiled_tension_background_task_stops_cooperatively(
    connected_mock_hand, monkeypatch
):
    hand = connected_mock_hand
    selected = [hand.config.joint_to_motor_map["index_mcp"]]
    writes = []
    client = hand.motor_client
    monkeypatch.setattr(client, "supports_profiled_position_writes", True)

    def profiled(motor_ids, positions, *, speed, acceleration, torque):
        writes.append((tuple(motor_ids), speed, acceleration, torque))
        return []

    monkeypatch.setattr(client, "write_desired_pos_profiled", profiled)

    hand.tension(
        blocking=False,
        motor_ids=selected,
        winding_current=120,
        hold_current=100,
        max_wind_s=0.001,
        profile_speed=10,
        profile_acceleration=5,
        profile_torque=120,
    )
    deadline = time.monotonic() + 1.0
    while not writes and time.monotonic() < deadline:
        time.sleep(0.001)

    assert writes
    assert hand.stop_task(timeout=1.0)
    assert not hand.task_running
    assert hand._position_write_profile is None
    assert all(item == ((selected[0],), 10, 5, 120) for item in writes)


def test_tension_cleanup_attempts_selected_disable_after_restore_failure(
    connected_mock_hand, monkeypatch
):
    from orca_core.maintenance.tensioning import run_tension

    selected = [connected_mock_hand.config.joint_to_motor_map["index_mcp"]]
    current_calls = 0
    disabled = []
    events = []

    def current(current, motor_ids=None):
        nonlocal current_calls
        current_calls += 1
        if current_calls > 1:
            raise RuntimeError("current restore failed")

    def disable(motor_ids=None):
        disabled.append(tuple(motor_ids or ()))
        return []

    monkeypatch.setattr(connected_mock_hand, "set_max_current", current)
    monkeypatch.setattr(connected_mock_hand, "disable_torque", disable)

    with pytest.raises(RuntimeError, match="current restore failed"):
        run_tension(
            connected_mock_hand,
            move_motors=False,
            motor_ids=selected,
            hold_duration_s=0.001,
            progress_callback=events.append,
        )

    assert disabled == [tuple(selected)]
    assert events[-1]["event"] == "phase"
    assert events[-1]["phase"] == "released"


def test_tension_enable_failure_triggers_selected_cleanup(
    connected_mock_hand, monkeypatch
):
    from orca_core.maintenance.tensioning import run_tension

    selected = [connected_mock_hand.config.joint_to_motor_map["index_mcp"]]
    enabled = []
    disabled = []

    def enable(motor_ids=None):
        enabled.append(tuple(motor_ids or ()))
        return list(motor_ids or ())

    def disable(motor_ids=None):
        disabled.append(tuple(motor_ids or ()))
        return []

    monkeypatch.setattr(connected_mock_hand, "enable_torque", enable)
    monkeypatch.setattr(connected_mock_hand, "disable_torque", disable)

    with pytest.raises(RuntimeError, match="torque enable failed"):
        run_tension(
            connected_mock_hand,
            move_motors=False,
            motor_ids=selected,
            hold_duration_s=0.001,
        )

    assert enabled == [tuple(selected)]
    assert disabled == [tuple(selected)]
