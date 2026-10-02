"""Ordinary-user result page backed by an unchanged technical ScanReport."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHBoxLayout,
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
from safeinstall.gui.presentation import ResultPresentation, present_report
from safeinstall.models import ScanReport, Severity


class ResultView(QWidget):
    back_requested = Signal()
    technical_requested = Signal()
    export_requested = Signal()

    def __init__(self, catalog: Catalog) -> None:
        super().__init__()
        self.catalog = catalog
        self.report: ScanReport | None = None
        self.presentation: ResultPresentation | None = None

        self.back_button = QPushButton()
        self.target_name = QLabel()
        self.target_name.setObjectName("Title")
        self.target_name.setTextFormat(Qt.TextFormat.PlainText)
        self.target_name.setWordWrap(True)
        self.risk_card = QFrame()
        self.risk_card.setObjectName("RiskCard")
        risk_layout = QVBoxLayout(self.risk_card)
        self.risk_caption = QLabel()
        self.risk_label = QLabel()
        self.risk_label.setObjectName("RiskLevel")
        risk_layout.addWidget(self.risk_caption)
        risk_layout.addWidget(self.risk_label)
        self.coverage_notice = QLabel()
        self.coverage_notice.setObjectName("CoverageNotice")
        self.coverage_notice.setTextFormat(Qt.TextFormat.PlainText)
        self.coverage_notice.setWordWrap(True)
        self.coverage_notice.hide()

        self.behavior_title = QLabel()
        self.behavior_title.setObjectName("SectionTitle")
        self.behaviors = QLabel()
        self.behaviors.setTextFormat(Qt.TextFormat.PlainText)
        self.behaviors.setWordWrap(True)
        self.checks = QLabel()
        self.checks.setObjectName("PositiveChecks")
        self.checks.setTextFormat(Qt.TextFormat.PlainText)
        self.checks.setWordWrap(True)

        self.why_title = QLabel()
        self.why_title.setObjectName("SectionTitle")
        self.why = QLabel()
        self.why.setTextFormat(Qt.TextFormat.PlainText)
        self.why.setWordWrap(True)

        self.capability_title = QLabel()
        self.capability_title.setObjectName("SectionTitle")
        self.capability_table = QTableWidget(0, 2)
        self.capability_table.verticalHeader().hide()
        self.capability_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        self.capability_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.ResizeToContents
        )
        self.capability_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.capability_table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.capability_table.setFocusPolicy(Qt.FocusPolicy.NoFocus)

        self.findings_title = QLabel()
        self.findings_title.setObjectName("SectionTitle")
        self.finding_table = QTableWidget(0, 3)
        self.finding_table.verticalHeader().hide()
        self.finding_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        self.finding_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.ResizeToContents
        )
        self.finding_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.ResizeToContents
        )
        self.finding_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.finding_table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)

        self.recommendation_title = QLabel()
        self.recommendation_title.setObjectName("SectionTitle")
        self.recommendation = QLabel()
        self.recommendation.setObjectName("Recommendation")
        self.recommendation.setTextFormat(Qt.TextFormat.PlainText)
        self.recommendation.setWordWrap(True)
        self.stats = QLabel()
        self.stats.setObjectName("Muted")

        self.ai_panel = QFrame()
        self.ai_panel.setObjectName("AIResultCard")
        ai_layout = QVBoxLayout(self.ai_panel)
        self.ai_title = QLabel()
        self.ai_title.setObjectName("SectionTitle")
        self.ai_advisory = QLabel()
        self.ai_advisory.setObjectName("Muted")
        self.ai_advisory.setWordWrap(True)
        self.ai_summary = QLabel()
        self.ai_summary.setTextFormat(Qt.TextFormat.PlainText)
        self.ai_summary.setWordWrap(True)
        self.ai_items = QLabel()
        self.ai_items.setTextFormat(Qt.TextFormat.PlainText)
        self.ai_items.setWordWrap(True)
        self.ai_context = QLabel()
        self.ai_context.setObjectName("Muted")
        self.ai_context.setTextFormat(Qt.TextFormat.PlainText)
        self.ai_context.setWordWrap(True)
        ai_layout.addWidget(self.ai_title)
        ai_layout.addWidget(self.ai_advisory)
        ai_layout.addWidget(self.ai_summary)
        ai_layout.addWidget(self.ai_items)
        ai_layout.addWidget(self.ai_context)
        self.ai_panel.hide()
        self.technical_button = QPushButton()
        self.export_button = QPushButton()
        actions = QHBoxLayout()
        actions.addWidget(self.technical_button)
        actions.addWidget(self.export_button)
        actions.addStretch()

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(64, 36, 64, 48)
        layout.setSpacing(14)
        layout.addWidget(self.back_button, alignment=Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(self.target_name)
        layout.addWidget(self.risk_card)
        layout.addWidget(self.coverage_notice)
        layout.addWidget(self.behavior_title)
        layout.addWidget(self.behaviors)
        layout.addWidget(self.checks)
        layout.addWidget(self.why_title)
        layout.addWidget(self.why)
        layout.addWidget(self.capability_title)
        layout.addWidget(self.capability_table)
        layout.addWidget(self.findings_title)
        layout.addWidget(self.finding_table)
        layout.addWidget(self.recommendation_title)
        layout.addWidget(self.recommendation)
        layout.addWidget(self.stats)
        layout.addWidget(self.ai_panel)
        layout.addLayout(actions)
        layout.addStretch()

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(content)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

        self.back_button.clicked.connect(self.back_requested)
        self.technical_button.clicked.connect(self.technical_requested)
        self.export_button.clicked.connect(self.export_requested)
        self.retranslate()

    def set_report(self, report: ScanReport) -> None:
        self.report = report
        self.presentation = present_report(report, self.catalog)
        value = self.presentation
        self.target_name.setText(value.target_name)
        self.risk_label.setText(value.risk_label)
        partial = report.coverage.status == "partial"
        self.risk_caption.setText(
            self.catalog.text("coverage.caption" if partial else "result.overall_risk")
        )
        card_level = value.risk_level.value
        if partial and value.risk_level is Severity.LOW:
            card_level = "incomplete"
        self.risk_card.setProperty("risk", card_level)
        self.coverage_notice.setText(value.coverage_notice)
        self.coverage_notice.setVisible(partial)
        self.risk_card.style().unpolish(self.risk_card)
        self.risk_card.style().polish(self.risk_card)
        self.behaviors.setText("\n".join(f"⚠ {item}" for item in value.behaviors))
        self.checks.setText("\n".join(f"✓ {item}" for item in value.bounded_checks))
        self.why.setText(value.why)
        self.recommendation.setText(value.recommendation)
        self.stats.setText(
            self.catalog.text(
                "result.stats",
                files=value.files_scanned,
                dependencies=value.dependencies,
                duration=value.duration_ms,
            )
        )
        self._fill_capabilities(value)
        self._fill_findings(value)
        self._fill_ai(value)

    def _fill_capabilities(self, value: ResultPresentation) -> None:
        self.capability_table.setRowCount(len(value.capabilities))
        for row, capability in enumerate(value.capabilities):
            self.capability_table.setItem(row, 0, QTableWidgetItem(capability.label))
            self.capability_table.setItem(row, 1, QTableWidgetItem(capability.value))
        self.capability_table.resizeRowsToContents()
        self.capability_table.setMinimumHeight(
            min(430, self.capability_table.verticalHeader().length() + 36)
        )

    def _fill_findings(self, value: ResultPresentation) -> None:
        self.finding_table.setRowCount(max(1, len(value.top_findings)))
        self.finding_table.clearSpans()
        if not value.top_findings:
            self.finding_table.setSpan(0, 0, 1, 3)
            self.finding_table.setItem(
                0,
                0,
                QTableWidgetItem(
                    self.catalog.text(
                        "result.partial_no_findings"
                        if value.coverage_notice
                        else "result.no_findings"
                    )
                ),
            )
        else:
            for row, finding in enumerate(value.top_findings):
                self.finding_table.setItem(row, 0, QTableWidgetItem(finding.name))
                self.finding_table.setItem(row, 1, QTableWidgetItem(finding.location))
                self.finding_table.setItem(row, 2, QTableWidgetItem(finding.severity_label))
        self.finding_table.resizeRowsToContents()
        self.finding_table.setMinimumHeight(
            min(240, self.finding_table.verticalHeader().length() + 36)
        )

    def _fill_ai(self, value: ResultPresentation) -> None:
        analysis = value.ai
        self.ai_panel.setVisible(analysis is not None)
        if analysis is None:
            self.ai_summary.clear()
            self.ai_items.clear()
            self.ai_context.clear()
            return
        priorities = "\n".join(f"• {item}" for item in analysis.top_risks)
        notes = "\n".join(f"• {item}" for item in analysis.review_notes)
        sections = [section for section in (priorities, notes) if section]
        self.ai_summary.setText(analysis.summary)
        self.ai_items.setText("\n\n".join(sections))
        self.ai_context.setText(
            f"{analysis.sent_context}\n{self.catalog.text('result.ai_model', model=analysis.model)}"
        )

    def retranslate(self) -> None:
        self.back_button.setText(self.catalog.text("common.back"))
        self.risk_caption.setText(self.catalog.text("result.overall_risk"))
        self.behavior_title.setText(self.catalog.text("result.may_do"))
        self.why_title.setText(self.catalog.text("result.why"))
        self.capability_title.setText(self.catalog.text("result.capabilities"))
        self.findings_title.setText(self.catalog.text("result.top_findings"))
        self.recommendation_title.setText(self.catalog.text("result.recommendation"))
        self.ai_title.setText(self.catalog.text("result.ai_title"))
        self.ai_advisory.setText(self.catalog.text("result.ai_advisory"))
        self.capability_table.setHorizontalHeaderLabels(
            [self.catalog.text("result.capability"), self.catalog.text("result.observed")]
        )
        self.finding_table.setHorizontalHeaderLabels(
            [
                self.catalog.text("result.finding"),
                self.catalog.text("result.location"),
                self.catalog.text("result.severity"),
            ]
        )
        self.technical_button.setText(self.catalog.text("result.technical"))
        self.export_button.setText(self.catalog.text("result.export"))
        if self.report is not None:
            self.set_report(self.report)
