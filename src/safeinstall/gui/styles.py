"""A restrained, high-contrast Qt Widgets theme."""

APPLICATION_STYLE = """
QWidget {
    color: #172033;
    font-family: "Segoe UI", "Noto Sans", sans-serif;
    font-size: 14px;
}
QMainWindow, QWidget#AppRoot { background: #f5f7fb; }
QFrame#Header { background: #ffffff; border-bottom: 1px solid #dde3ee; }
QLabel#Brand { color: #123c69; font-size: 22px; font-weight: 700; }
QLabel#Title { color: #102a43; font-size: 30px; font-weight: 700; }
QLabel#Tagline { color: #52637a; font-size: 16px; }
QFrame#DropZone {
    background: #ffffff;
    border: 2px dashed #8ea8c7;
    border-radius: 14px;
}
QFrame#SelectionCard {
    background: #f8fafc;
    border: 1px solid #dbe3ed;
    border-radius: 10px;
    padding: 10px;
}
QLabel#ReadyStatus {
    color: #18794e;
    font-weight: 700;
}
QLabel#ReadyStatus[unsupported="true"] {
    color: #b42318;
}
QLabel#PrivacyNotice {
    background: #eef5ff;
    border: 1px solid #c8dcfa;
    border-radius: 8px;
    color: #244b75;
    padding: 14px;
}
QProgressBar {
    min-height: 12px;
    border: 1px solid #ccd6e3;
    border-radius: 6px;
    background: #eef2f7;
}
QProgressBar::chunk {
    background: #2f6feb;
    border-radius: 5px;
}
QFrame#RiskCard {
    background: #eff8f2;
    border-left: 6px solid #27864a;
    border-radius: 8px;
    padding: 16px;
}
QFrame#RiskCard[risk="medium"], QFrame#RiskCard[risk="incomplete"] {
    background: #fff8e6;
    border-left-color: #b7791f;
}
QFrame#RiskCard[risk="high"] {
    background: #fff0ee;
    border-left-color: #d64545;
}
QFrame#RiskCard[risk="critical"] {
    background: #f9e8e8;
    border-left-color: #8b1e1e;
}
QLabel#RiskLevel {
    font-size: 28px;
    font-weight: 800;
}
QLabel#SectionTitle {
    font-size: 18px;
    font-weight: 700;
    margin-top: 10px;
}
QLabel#PositiveChecks {
    color: #276749;
}
QLabel#CoverageNotice {
    background: #fff8e6;
    color: #704a0d;
    border: 1px solid #e4c681;
    border-radius: 8px;
    padding: 14px;
}
QLabel#Recommendation {
    background: #f6f8fa;
    border: 1px solid #d8dee4;
    border-radius: 8px;
    padding: 14px;
}
QFrame#DetailsCard {
    background: #f8fafc;
    border: 1px solid #dbe3ed;
    border-radius: 8px;
    padding: 12px;
}
QFrame#AIResultCard {
    background: #f2f4ff;
    border: 1px solid #cdd4f6;
    border-radius: 8px;
    padding: 14px;
}
QFrame#DropZone[dragActive="true"] { background: #eaf3ff; border-color: #2563a9; }
QLabel#DropTitle { color: #173b63; font-size: 18px; font-weight: 600; }
QLabel#Muted { color: #65758b; }
QPushButton {
    background: #ffffff;
    border: 1px solid #bcc9d9;
    border-radius: 8px;
    padding: 9px 16px;
    font-weight: 600;
}
QPushButton:hover { border-color: #3978b8; background: #f3f8fd; }
QPushButton:disabled { color: #8c99aa; background: #edf1f6; border-color: #d5dce6; }
QPushButton#PrimaryButton { background: #1769aa; color: white; border-color: #1769aa; }
QPushButton#PrimaryButton:hover { background: #12598f; }
QLineEdit, QComboBox {
    background: #ffffff;
    border: 1px solid #bcc9d9;
    border-radius: 8px;
    padding: 9px 11px;
}
QLineEdit:focus, QComboBox:focus { border-color: #1769aa; }
QPushButton#NavButton {
    background: transparent;
    border: 0;
    color: #36536f;
    padding: 7px 10px;
}
QPushButton#NavButton:hover { background: #eef5ff; }
QLabel#StatusNotice {
    color: #36536f;
    background: #f6f8fa;
    border: 1px solid #d8dee4;
    border-radius: 6px;
    padding: 10px;
}
"""
