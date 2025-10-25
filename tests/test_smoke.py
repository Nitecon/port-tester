import os
import sys
import time
import importlib

# Force offscreen for headless CI
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


def test_mainwindow_smoke(qtbot):
    app_module = importlib.import_module("app")
    MainWindow = getattr(app_module, "MainWindow")

    w = MainWindow()
    qtbot.addWidget(w)
    w.show()

    # Allow event loop to process briefly
    qtbot.waitUntil(lambda: w.isVisible(), timeout=2000)
    assert w.windowTitle() == "UDP/TCP Port Tester"

    # Close cleanly
    w.close()
