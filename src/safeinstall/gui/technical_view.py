"""Evidence-first technical finding browser for developers and reviewers."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFormLayout,
    QFrame,
    QHeaderView,
    QLabel,
    QPushButton,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from safeinstall.gui.i18n import Catalog
from safeinstall.gui.presentation import coverage_notice
from safeinstall.models import Finding, FindingConfidence, ScanReport
from safeinstall.redaction import redact_text

MAX_UI_FINDINGS = 1_000


class TechnicalDetailsView(QWidget):
    back_requested = Signal()

    def __init__(self, catalog: Catalog) -> None:
        super().__init__()
        self.catalog = catalog
        self.report: ScanReport | None = None
        self._findings: tuple[Finding, ...] = ()

        self.back_button = QPushButton()
        self.title = QLabel()
        self.title.setObjectName("Title")
        self.score = QLabel()
        self.score.setObjectName("Muted")
        self.coverage_notice = self._plain_label()
        self.coverage_notice.setObjectName("CoverageNotice")
        self.coverage_notice.hide()
        self.limit_notice = QLabel()
        self.limit_notice.setObjectName("Muted")
        self.limit_notice.setWordWrap(True)
        self.limit_notice.hide()

        self.finding_table = QTableWidget(0, 5)
        self.finding_table.verticalHeader().hide()
        self.finding_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.finding_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.finding_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.finding_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents
        )
        self.finding_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.ResizeToContents
        )
        self.finding_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.Stretch
        )
        self.finding_table.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeMode.ResizeToContents
        )
        self.finding_table.horizontalHeader().setSectionResizeMode(
            4, QHeaderView.ResizeMode.Stretch
        )

        details = QFrame()
        details.setObjectName("DetailsCard")
        form = QFormLayout(details)
        self.rule_value = self._plain_label()
        self.severity_value = self._plain_label()
        self.category_value = self._plain_label()
        self.file_value = self._plain_label()
        self.line_value = self._plain_label()
        self.basis_value = self._plain_label()
        self.capabilities_value = self._plain_label()
        self.rule_heading = QLabel()
        self.severity_heading = QLabel()
        self.category_heading = QLabel()
        self.file_heading = QLabel()
        self.line_heading = QLabel()
        self.basis_heading = QLabel()
        self.capabilities_heading = QLabel()
        form.addRow(self.rule_heading, self.rule_value)
        form.addRow(self.severity_heading, self.severity_value)
        form.addRow(self.category_heading, self.category_value)
        form.addRow(self.file_heading, self.file_value)
        form.addRow(self.line_heading, self.line_value)
        form.addRow(self.basis_heading, self.basis_value)
        form.addRow(self.capabilities_heading, self.capabilities_value)

        self.fact_heading = self._section_heading()
        self.fact_value = self._plain_label()
        self.inference_heading = self._section_heading()
        self.inference_value = self._plain_label()
        self.advice_heading = self._section_heading()
        self.advice_value = self._plain_label()

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(56, 34, 56, 48)
        layout.setSpacing(12)
        layout.addWidget(self.back_button, alignment=Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(self.title)
        layout.addWidget(self.score)
        layout.addWidget(self.coverage_notice)
        layout.addWidget(self.limit_notice)
        layout.addWidget(self.finding_table)
        layout.addWidget(details)
        layout.addWidget(self.fact_heading)
        layout.addWidget(self.fact_value)
        layout.addWidget(self.inference_heading)
        layout.addWidget(self.inference_value)
        layout.addWidget(self.advice_heading)
        layout.addWidget(self.advice_value)
        layout.addStretch()

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(content)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

        self.back_button.clicked.connect(self.back_requested)
        self.finding_table.currentCellChanged.connect(
            lambda row, _column, _previous_row, _previous_column: self.show_finding(row)
        )
        self.retranslate()

    @staticmethod
    def _plain_label() -> QLabel:
        label = QLabel()
        label.setTextFormat(Qt.TextFormat.PlainText)
        label.setWordWrap(True)
        label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        return label

    @staticmethod
    def _section_heading() -> QLabel:
        label = QLabel()
        label.setObjectName("SectionTitle")
        return label

    def set_report(self, report: ScanReport) -> None:
        self.report = report
        self._findings = report.findings[:MAX_UI_FINDINGS]
        self.coverage_notice.setText(coverage_notice(report, self.catalog))
        self.coverage_notice.setVisible(report.coverage.status == "partial")
        self.score.setText(
            self.catalog.text(
                "technical.partial_score"
                if report.coverage.status == "partial"
                else "technical.score",
                level=report.risk.level.value.upper(),
                score=report.risk.score,
            )
        )
        omitted = len(report.findings) - len(self._findings)
        self.limit_notice.setVisible(omitted > 0)
        if omitted > 0:
            self.limit_notice.setText(self.catalog.text("technical.omitted", count=omitted))
        self.finding_table.setRowCount(len(self._findings))
        for row, finding in enumerate(self._findings):
            evidence = finding.evidence[0]
            values = (
                finding.rule_id,
                finding.severity.value.upper(),
                evidence.path,
                str(evidence.line or "—"),
                finding.name,
            )
            for column, value in enumerate(values):
                self.finding_table.setItem(row, column, QTableWidgetItem(redact_text(value)))
        self.finding_table.setMinimumHeight(
            min(390, self.finding_table.verticalHeader().length() + 36)
        )
        if self._findings:
            self.finding_table.selectRow(0)
            self.show_finding(0)
        else:
            self._clear_details()

    def show_finding(self, row: int) -> None:
        if not 0 <= row < len(self._findings):
            return
        finding = self._findings[row]
        evidence = finding.evidence[0]
        basis_key = (
            "technical.observed"
            if finding.confidence is FindingConfidence.OBSERVED
            else "technical.inferred"
        )
        self.rule_value.setText(finding.rule_id)
        self.severity_value.setText(finding.severity.value.upper())
        self.category_value.setText(finding.category)
        self.file_value.setText(redact_text(evidence.path))
        self.line_value.setText(str(evidence.line or "—"))
        self.basis_value.setText(self.catalog.text(basis_key))
        self.capabilities_value.setText(
            ", ".join(
                self.catalog.text(f"capability.{capability.value}")
                for capability in finding.capabilities
            )
            or self.catalog.text("common.none")
        )
        fact = redact_text(finding.description)
        if evidence.snippet:
            evidence_label = self.catalog.text("technical.evidence")
            fact = f"{fact}\n\n{evidence_label}:\n{redact_text(evidence.snippet)}"
        self.fact_value.setText(fact)
        self.inference_value.setText(redact_text(finding.explanation))
        self.advice_value.setText(redact_text(finding.recommendation))

    def _clear_details(self) -> None:
        for label in (
            self.rule_value,
            self.severity_value,
            self.category_value,
            self.file_value,
            self.line_value,
            self.basis_value,
            self.capabilities_value,
            self.fact_value,
            self.inference_value,
            self.advice_value,
        ):
            label.setText("—")

    def retranslate(self) -> None:
        self.back_button.setText(self.catalog.text("common.back"))
        self.title.setText(self.catalog.text("technical.title"))
        headings = (
            "technical.rule",
            "technical.severity",
            "technical.file",
            "technical.line",
            "technical.finding",
        )
        self.finding_table.setHorizontalHeaderLabels([self.catalog.text(key) for key in headings])
        for label, key in (
            (self.rule_heading, "technical.rule"),
            (self.severity_heading, "technical.severity"),
            (self.category_heading, "technical.category"),
            (self.file_heading, "technical.file"),
            (self.line_heading, "technical.line"),
            (self.basis_heading, "technical.basis"),
            (self.capabilities_heading, "technical.capabilities"),
            (self.fact_heading, "technical.fact"),
            (self.inference_heading, "technical.assessment"),
            (self.advice_heading, "technical.advice"),
        ):
            label.setText(self.catalog.text(key))
        if self.report is not None:
            self.set_report(self.report)
