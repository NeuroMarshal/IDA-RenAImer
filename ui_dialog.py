# ui_dialog.py – AI Assistant settings dialog
import threading
import traceback
from functools import partial

try:
    from PyQt5 import QtCore, QtWidgets  # type: ignore
except ImportError:
    QtCore = QtWidgets = None

import ida_kernwin  # type: ignore
from settings import AIAssistantSettings
from lmm_bridge import OllamaClient
from logger import log_info, log_debug, log_error, log_warning

class AIAssistantSettingsDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(QtCore.Qt.WA_DeleteOnClose)
        self.setWindowTitle("AI Assistant — settings")
        self.resize(800, 620)
        self.setModal(True)

        self._setup_ui()
        self._load_settings()
        QtCore.QTimer.singleShot(0, self._async_test_connection)

    def _setup_ui(self):
        main_layout = QtWidgets.QVBoxLayout(self)
        self.tabs = QtWidgets.QTabWidget()
        main_layout.addWidget(self.tabs)

        self._init_connection_tab()
        self._init_models_tab()
        self._init_prompts_tab()
        self._init_analysis_tab()

        btn_layout = QtWidgets.QHBoxLayout()
        self.btn_reset = QtWidgets.QPushButton("Reset to defaults")
        self.btn_reset.clicked.connect(self._reset_defaults)
        btn_layout.addWidget(self.btn_reset)

        btn_layout.addStretch()
        btn_box = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel
        )
        btn_box.accepted.connect(self._save_and_close)
        btn_box.rejected.connect(self.reject)
        btn_layout.addWidget(btn_box)

        main_layout.addLayout(btn_layout)

    def _init_connection_tab(self):
        tab = QtWidgets.QWidget()
        self.tabs.addTab(tab, "Connection")
        form = QtWidgets.QFormLayout(tab)

        self.ed_url = QtWidgets.QLineEdit()
        form.addRow("URL Ollama:", self.ed_url)


        self.cb_autodetect = QtWidgets.QCheckBox("Auto-discover models")
        form.addRow("", self.cb_autodetect)

        h = QtWidgets.QHBoxLayout()
        self.btn_test = QtWidgets.QPushButton("Test")
        self.btn_test.clicked.connect(self._async_test_connection)
        h.addWidget(self.btn_test)
        self.lab_status = QtWidgets.QLabel("Status — not tested")
        h.addWidget(self.lab_status)
        h.addStretch()
        form.addRow(h)

        self.cmb_debug = QtWidgets.QComboBox()
        self.cmb_debug.addItems(["Info", "Debug"])
        form.addRow("Log level:", self.cmb_debug)

        self.cb_show_thinking = QtWidgets.QCheckBox("Show thinking")
        self.cb_show_reasoning = QtWidgets.QCheckBox("Show reasoning")
        form.addRow("", self.cb_show_thinking)
        form.addRow("", self.cb_show_reasoning)

    def _init_models_tab(self):
        tab = QtWidgets.QWidget()
        self.tabs.addTab(tab, "Models")
        v = QtWidgets.QVBoxLayout(tab)

        self.models_table = QtWidgets.QTableWidget(0, 3)
        self.models_table.setHorizontalHeaderLabels(["Model", "In menu", "Thinking"])
        self.models_table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.models_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.models_table.setSelectionMode(QtWidgets.QAbstractItemView.NoSelection)
        self.models_table.setFocusPolicy(QtCore.Qt.NoFocus)
        v.addWidget(self.models_table)

        h = QtWidgets.QHBoxLayout()
        h.addStretch()
        self.btn_refresh = QtWidgets.QPushButton("🔄 Refresh from Ollama")
        self.btn_refresh.clicked.connect(self._refresh_models_from_ollama)
        h.addWidget(self.btn_refresh)
        v.addLayout(h)

        self._refresh_models()

    def _init_prompts_tab(self):
        tab = QtWidgets.QWidget()
        self.tabs.addTab(tab, "Prompts")
        v = QtWidgets.QVBoxLayout(tab)

        label_sys = QtWidgets.QLabel("System prompt:")
        label_sys.setSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        label_sys.setMaximumHeight(32)
        v.addWidget(label_sys)

        self.ed_sys_prompt = QtWidgets.QTextEdit()
        v.addWidget(self.ed_sys_prompt)

        label_user = QtWidgets.QLabel("User prompt:")
        label_user.setSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        label_user.setMaximumHeight(32)
        v.addWidget(label_user)

        self.ed_user_prompt = QtWidgets.QTextEdit()
        v.addWidget(self.ed_user_prompt)

    def _init_analysis_tab(self):
        tab = QtWidgets.QWidget()
        self.tabs.addTab(tab, "Analysis")
        form = QtWidgets.QFormLayout(tab)

        self.sb_temperature = QtWidgets.QDoubleSpinBox()
        self.sb_temperature.setMaximum(999.99)
        self.sb_temperature.setDecimals(2)
        self.sb_temperature.setSingleStep(0.05)
        form.addRow("Temperature:", self.sb_temperature)

        self.seed = QtWidgets.QSpinBox()
        self.seed.setMaximum(999999)
        self.seed.setSingleStep(64)
        form.addRow("seed", self.seed)

        self.sb_numctx = QtWidgets.QSpinBox()
        self.sb_numctx.setMaximum(999999)
        self.sb_numctx.setSingleStep(256)
        form.addRow("num_ctx:", self.sb_numctx)

        self.sb_num_predict = QtWidgets.QSpinBox()
        self.sb_num_predict.setMaximum(999999)
        self.sb_num_predict.setSingleStep(64)
        form.addRow("num_predict:", self.sb_num_predict)

        self.max_called_functions = QtWidgets.QSpinBox()
        self.max_called_functions.setMaximum(999999)
        self.max_called_functions.setSingleStep(64)
        form.addRow("max_called_functions", self.max_called_functions)

        self.max_calling_functions = QtWidgets.QSpinBox()
        self.max_calling_functions.setMaximum(999999)
        self.max_calling_functions.setSingleStep(64)
        form.addRow("max_calling_functions", self.max_calling_functions)
        
        self.comment_max_line_length = QtWidgets.QSpinBox()
        self.comment_max_line_length.setMaximum(999999)
        self.comment_max_line_length.setSingleStep(64)
        form.addRow("comment_max_line_length", self.comment_max_line_length)

    def _load_settings(self):
        s = AIAssistantSettings.instance()
        self.ed_url.setText(s.get("ollama_url", ""))
        self.cb_autodetect.setChecked(s.get("auto_discover_models", False))
        self.cmb_debug.setCurrentIndex(1 if s.get("debug", 0) else 0)
        self.cb_show_thinking.setChecked(s.get("display_thinking", False))
        self.cb_show_reasoning.setChecked(s.get("display_reasoning", False))
        self.ed_sys_prompt.setPlainText(s.get("system_prompt", ""))
        self.ed_user_prompt.setPlainText(s.get("user_prompt", ""))
        self.sb_temperature.setValue(s.get("temperature", 1.0))
        self.seed.setValue(s.get("seed",0))
        self.sb_numctx.setValue(s.get("num_ctx", 4096))
        self.sb_num_predict.setValue(s.get("num_predict", 512))
        self.max_called_functions.setValue(s.get("max_called_functions", 8))
        self.max_calling_functions.setValue(s.get("max_calling_functions", 4))
        self.comment_max_line_length.setValue(s.get("comment_max_line_length",128))
        self._refresh_models()

    def _save_and_close(self):
        s = AIAssistantSettings.instance()
        s.set("ollama_url", self.ed_url.text())
        s.set("auto_discover_models", self.cb_autodetect.isChecked())
        s.set("debug", int(self.cmb_debug.currentIndex() == 1))
        s.set("display_thinking", self.cb_show_thinking.isChecked())
        s.set("display_reasoning", self.cb_show_reasoning.isChecked())
        s.set("system_prompt", self.ed_sys_prompt.toPlainText())
        s.set("user_prompt", self.ed_user_prompt.toPlainText())
        s.set("temperature", self.sb_temperature.value())
        s.set("seed",self.seed.value())
        s.set("num_ctx", self.sb_numctx.value())
        s.set("num_predict", self.sb_num_predict.value())
        s.set("max_called_functions",self.max_called_functions.value())
        s.set("max_calling_functions",self.max_calling_functions.value())
        s.set("comment_max_line_length",self.comment_max_line_length.value())
        s.save_settings()
        self.accept()

    def _refresh_models(self):
        self.models_table.setRowCount(0)
        models = AIAssistantSettings.instance().get("available_models", [])
        for model in models:
            row = self.models_table.rowCount()
            self.models_table.insertRow(row)
            name_item = QtWidgets.QTableWidgetItem(model.get("display_name", model["name"]))
            name_item.setData(QtCore.Qt.UserRole, model)
            self.models_table.setItem(row, 0, name_item)

            enabled_cb = QtWidgets.QCheckBox()
            enabled_cb.setChecked(model.get("enabled", True))
            enabled_cb.stateChanged.connect(partial(self._on_enabled_changed, model["name"]))
            w1 = QtWidgets.QWidget()
            l1 = QtWidgets.QHBoxLayout(w1)
            l1.addWidget(enabled_cb); l1.setAlignment(QtCore.Qt.AlignCenter); l1.setContentsMargins(0,0,0,0)
            self.models_table.setCellWidget(row, 1, w1)

            thinking_cb = QtWidgets.QCheckBox()
            thinking_cb.setChecked(model.get("thinking", False))
            thinking_cb.stateChanged.connect(partial(self._on_thinking_changed, model["name"]))
            w2 = QtWidgets.QWidget()
            l2 = QtWidgets.QHBoxLayout(w2)
            l2.addWidget(thinking_cb); l2.setAlignment(QtCore.Qt.AlignCenter); l2.setContentsMargins(0,0,0,0)
            self.models_table.setCellWidget(row, 2, w2)

    def _refresh_models_from_ollama(self):
        self.btn_refresh.setEnabled(False); self.btn_refresh.setText("Refreshing...")
        def work():
            try:
                ollama_client = OllamaClient()
                ollama_models = ollama_client.get_models()
                existing = AIAssistantSettings.instance().get("available_models", [])
                names = {m["name"] for m in existing}
                new = [
                    {"name": n, "display_name": n.split(":")[0].title(), "enabled": True, "thinking": False, "auto_discovered": True}
                    for n in ollama_models if n not in names
                ]
                if new:
                    settings = AIAssistantSettings.instance()
                    settings.set("available_models", existing + new)
                    settings.save_settings()
                QtCore.QMetaObject.invokeMethod(
                    self, "_on_models_updated",
                    QtCore.Qt.QueuedConnection,
                    QtCore.Q_ARG(int, len(new))
                )
            except Exception as e:
                QtCore.QMetaObject.invokeMethod(
                    self, "_on_models_update_error",
                    QtCore.Qt.QueuedConnection,
                    QtCore.Q_ARG(str, str(e))
                )
        threading.Thread(target=work, daemon=True).start()

    @QtCore.pyqtSlot(int)
    def _on_models_updated(self, count):
        self.btn_refresh.setEnabled(True); self.btn_refresh.setText("🔄 Refresh from Ollama")
        self._refresh_models()
        msg = f"Added {count} new models" if count else "No new models found"
        log_info(msg)

    def _on_enabled_changed(self, name, state):
        models = AIAssistantSettings.instance().get("available_models", [])
        for m in models:
            if m["name"] == name:
                m["enabled"] = (state == QtCore.Qt.Checked)
                break
        AIAssistantSettings.instance().set("available_models", models)

    def _on_thinking_changed(self, name, state):
        models = AIAssistantSettings.instance().get("available_models", [])
        for m in models:
            if m["name"] == name:
                m["thinking"] = (state == QtCore.Qt.Checked)
                break
        AIAssistantSettings.instance().set("available_models", models)

    def _async_test_connection(self):
        self.btn_test.setEnabled(False); self.lab_status.setText("Checking…")
        def work():
            ollama_client = OllamaClient()
            ok, msg = ollama_client.test_connection()
            QtCore.QMetaObject.invokeMethod(
                self, "_on_connection_result",
                QtCore.Qt.QueuedConnection,
                QtCore.Q_ARG(bool, ok), QtCore.Q_ARG(str, msg)
            )
        threading.Thread(target=work, daemon=True).start()

    @QtCore.pyqtSlot(bool, str)
    def _on_connection_result(self, ok, msg):
        self.lab_status.setText(msg)
        self.lab_status.setStyleSheet("color: green;" if ok else "color: red;")
        self.btn_test.setEnabled(True)

    def _reset_defaults(self):
        if ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, "Reset all settings to defaults?") == ida_kernwin.ASKBTN_YES:
            settings = AIAssistantSettings.instance(); settings.reset_to_defaults(); settings.save_settings(); self._load_settings()
