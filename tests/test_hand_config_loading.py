"""Config-loading edge cases: empty config files and sensors.baudrate values."""

import os
import shutil

import pytest
import yaml

from orca_core.hand_config import (
    HandConfigValidationError,
    OrcaHandConfig,
    OrcaHandTouchConfig,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ORCA_CONFIG = os.path.join(
    REPO_ROOT, "orca_core", "models", "v2", "orcahand-right", "config.yaml"
)
TOUCH_CONFIG = os.path.join(
    REPO_ROOT, "orca_core", "models", "v2", "orcahand-touch-right", "config.yaml"
)


def test_empty_config_yaml_raises_clear_error(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("", encoding="utf-8")
    with pytest.raises(HandConfigValidationError, match="is empty"):
        OrcaHandConfig.from_config_path(config_path=str(config_path))


def test_comments_only_config_yaml_raises_clear_error(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("# truncated by an interrupted write\n", encoding="utf-8")
    with pytest.raises(HandConfigValidationError, match="config.yaml"):
        OrcaHandTouchConfig.from_config_path(config_path=str(config_path))


def _touch_config_with_baudrate(tmp_path, baudrate):
    config_path = tmp_path / "config.yaml"
    shutil.copy(TOUCH_CONFIG, config_path)
    with open(config_path) as f:
        doc = yaml.safe_load(f)
    doc.setdefault("sensors", {})["baudrate"] = baudrate
    with open(config_path, "w") as f:
        yaml.safe_dump(doc, f, sort_keys=False)
    return config_path


def _orca_config_with_overrides(tmp_path, **overrides):
    config_path = tmp_path / "config.yaml"
    shutil.copy(ORCA_CONFIG, config_path)
    with open(config_path) as f:
        doc = yaml.safe_load(f)
    doc.update(overrides)
    with open(config_path, "w") as f:
        yaml.safe_dump(doc, f, sort_keys=False)
    return config_path


def test_sensors_baudrate_auto_loads_as_auto(tmp_path):
    config_path = _touch_config_with_baudrate(tmp_path, "auto")
    config = OrcaHandTouchConfig.from_config_path(config_path=str(config_path))
    assert config.sensor_baudrate == "auto"


def test_sensors_baudrate_int_loads_as_int(tmp_path):
    config_path = _touch_config_with_baudrate(tmp_path, 921600)
    config = OrcaHandTouchConfig.from_config_path(config_path=str(config_path))
    assert config.sensor_baudrate == 921600


def test_feetech_configuration_contract_loads_without_hardware(tmp_path):
    config_path = _orca_config_with_overrides(
        tmp_path,
        motor_type="feetech",
        baudrate=1_000_000,
        max_current=300,
        calibration_current=200,
        wrist_calibration_current=150,
        calibration_step_size=0.1,
        calibration_step_period=0.01,
        calibration_threshold=0.01,
        calibration_num_stable=2,
    )

    config = OrcaHandConfig.from_config_path(config_path=str(config_path))

    assert config.motor_type == "feetech"
    assert config.baudrate == 1_000_000
    assert config.wrist_calibration_current == 150


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"motor_type": "feetech", "baudrate": 3_000_000}, "not supported"),
        ({"max_current": 200, "wrist_calibration_current": 201}, "wrist"),
        ({"calibration_current": 0}, "must be positive"),
        ({"calibration_step_size": 0}, "Calibration parameters must be positive"),
        ({"calibration_step_period": 0}, "Calibration parameters must be positive"),
        ({"calibration_threshold": 0}, "Calibration parameters must be positive"),
        ({"calibration_num_stable": 1}, "at least two samples"),
    ],
)
def test_invalid_motor_and_calibration_parameters_fail_before_hardware(
    tmp_path, overrides, message
):
    config_path = _orca_config_with_overrides(tmp_path, **overrides)

    with pytest.raises(HandConfigValidationError, match=message):
        OrcaHandConfig.from_config_path(config_path=str(config_path))


def test_write_yaml_atomic_exported_from_utils():
    from orca_core.utils import write_yaml_atomic
    from orca_core.utils.utils import write_yaml_atomic as impl

    assert write_yaml_atomic is impl
