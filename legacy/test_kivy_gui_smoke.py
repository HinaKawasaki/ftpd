"""GUI 冒烟测试。

需要一个能创建窗口的显示环境。没有显示时整体跳过，
所以在 CI / 无头环境下不会把测试判成失败。

推荐这样跑：:

    DISPLAY=:99 SDL_VIDEODRIVER=x11 pytest tests/test_gui_smoke.py
"""

from __future__ import annotations

import pytest

pytest.importorskip("kivy")

try:  # 导入 gui 会加载 KV 并初始化窗口，没有显示就会在这里失败
    from legacy.kivy_gui import FTPDApp, RootWidget
    from ftpd.db import UserDB
except Exception as exc:  # pragma: no cover - 取决于运行环境
    pytest.skip(f"无法初始化 Kivy 界面：{exc}", allow_module_level=True)


@pytest.fixture
def app(tmp_path):
    db = UserDB(tmp_path / "users.db")
    application = FTPDApp(db)
    root = application.build()
    application.root = root  # 平时由 App.run() 完成
    application._booted = True
    application._load_settings()
    application.refresh_users()
    yield application
    if application.service.running:
        application.service.stop()
    db.close()


def test_kv_layout_is_loaded(app):
    ids = app.root.ids
    for name in [
        "tabs", "username_input", "password_input", "user_grid",
        "dir_input", "port_input", "readonly_switch", "tls_switch",
        "autostop_input", "start_button", "stop_button",
        "log_label", "log_scroll", "status_bar",
    ]:
        assert name in ids, f"KV 里缺少 id: {name}"
    assert len(app.root.ids.tabs.tab_list) == 3


def test_add_user_through_the_ui(app):
    app.root.ids.username_input.text = "dave"
    app.root.ids.password_input.text = "secret123"
    app.action_add_user()

    assert app.db.get_user("dave") is not None
    assert app.selected_username == "dave"
    # 表单应被清空
    assert app.root.ids.username_input.text == ""
    assert app.root.ids.password_input.text == ""
    # 列表里应该出现这一行
    assert len(app.root.ids.user_grid.children) == 1


def test_add_user_rejects_bad_input(app):
    app.root.ids.username_input.text = "bad name"
    app.root.ids.password_input.text = "secret123"
    app.action_add_user()
    assert app.db.count_users() == 0


def test_toggle_enabled_through_the_ui(app):
    app.root.ids.username_input.text = "dave"
    app.root.ids.password_input.text = "secret123"
    app.action_add_user()

    app.action_toggle_enabled()
    assert app.db.get_user("dave").enabled is False

    app.action_toggle_enabled()
    assert app.db.get_user("dave").enabled is True


def test_toggle_without_selection_is_harmless(app):
    app.selected_username = ""
    app.action_toggle_enabled()  # 不应抛异常
    app.action_reset_password()
    app.action_delete_user()
    assert app.db.count_users() == 0


def test_reset_password_through_the_ui(app):
    app.root.ids.username_input.text = "dave"
    app.root.ids.password_input.text = "secret123"
    app.action_add_user()

    app.root.ids.password_input.text = "brandnew1"
    app.action_reset_password()

    assert app.db.verify("dave", "brandnew1") is True
    assert app.db.verify("dave", "secret123") is False


def test_collect_config_reads_the_form(app, tmp_path):
    share = tmp_path / "share"
    share.mkdir()
    app.root.ids.dir_input.text = str(share)
    app.root.ids.port_input.text = "2323"
    app.root.ids.readonly_switch.active = False
    app.root.ids.tls_switch.active = False
    app.root.ids.autostop_input.text = "2.5"

    cfg = app._collect_config()
    assert cfg.directory == share
    assert cfg.port == 2323
    assert cfg.readonly is False
    assert cfg.use_tls is False
    assert cfg.auto_stop_minutes == 2.5


def test_collect_config_rejects_bad_values(app, tmp_path):
    share = tmp_path / "share"
    share.mkdir()
    app.root.ids.dir_input.text = str(share)

    app.root.ids.port_input.text = "abc"
    with pytest.raises(Exception):
        app._collect_config()

    app.root.ids.port_input.text = "2121"
    app.root.ids.autostop_input.text = "-1"
    with pytest.raises(Exception):
        app._collect_config()


def test_collect_config_rejects_missing_directory(app, tmp_path):
    app.root.ids.dir_input.text = str(tmp_path / "nope")
    with pytest.raises(Exception):
        app._collect_config()


def test_logs_flow_into_the_label(app):
    app.log("第一条")
    app.log("第二条")
    app._drain_logs(0)
    text = app.root.ids.log_label.text
    assert "第一条" in text and "第二条" in text

    app.action_clear_log()
    assert app.root.ids.log_label.text == "（暂无日志）"


def test_settings_persist(app, tmp_path):
    share = tmp_path / "share"
    share.mkdir()
    app.root.ids.dir_input.text = str(share)
    app.root.ids.port_input.text = "2323"
    app._save_settings(app._collect_config())

    app._load_settings()
    assert app.root.ids.port_input.text == "2323"
    assert app.root.ids.dir_input.text == str(share)
