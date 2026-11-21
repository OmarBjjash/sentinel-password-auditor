"""
Interactive Password Checker View for Sentinel Password Auditor.

Allows users to input a proposed password, evaluates dictionary exposure (O(1)),
calculates password strength scoring, verifies policy compliance, and provides
actionable security recommendations. Passwords are never logged or stored.
"""

import logging
from typing import Any, Optional

import customtkinter as ctk

from core.config import (
    BG_CARD,
    BG_DARK,
    BG_HOVER,
    BG_INPUT,
    BG_MAIN,
    BORDER_COLOR,
    BTN_SECONDARY_BORDER,
    BTN_SECONDARY_FG,
    BTN_SECONDARY_HOVER,
    DANGER,
    PRIMARY,
    PRIMARY_HOVER,
    SUCCESS,
    TEXT_MUTED,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
    WARNING,
)
from core.dictionary_manager import DictionaryManager
from core.password_checker import StrengthLevel, check_dictionary, evaluate_strength
from core.password_policy import PasswordPolicy

logger = logging.getLogger(__name__)


class PasswordCheckerView(ctk.CTkFrame):
    """Interactive Password Checker GUI page with professional styling."""

    def __init__(
        self,
        master: Any,
        dict_manager: DictionaryManager,
        **kwargs: Any,
    ) -> None:
        super().__init__(master, fg_color=BG_MAIN, **kwargs)
        self.dict_manager = dict_manager
        self.policy = PasswordPolicy()
        self.is_password_visible: bool = False

        self._build_ui()

    def _build_ui(self) -> None:
        # Header
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=30, pady=(24, 12))

        ctk.CTkLabel(
            header,
            text="Interactive Password Evaluator",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color=TEXT_PRIMARY,
        ).pack(anchor="w")

        ctk.CTkLabel(
            header,
            text="Evaluate proposed passwords against common dictionary wordlists, complexity metrics, and policy rules.",
            font=ctk.CTkFont(size=12),
            text_color=TEXT_SECONDARY,
        ).pack(anchor="w", pady=(2, 0))

        # Main Scrollable Container
        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=30, pady=(0, 20))

        # Input Card
        input_card = ctk.CTkFrame(
            scroll,
            fg_color=BG_CARD,
            corner_radius=8,
            border_width=1,
            border_color=BORDER_COLOR,
        )
        input_card.pack(fill="x", pady=(0, 14), ipady=8)

        ctk.CTkLabel(
            input_card,
            text="Candidate Password Input",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=PRIMARY,
        ).pack(anchor="w", padx=20, pady=(14, 8))

        input_row = ctk.CTkFrame(input_card, fg_color="transparent")
        input_row.pack(fill="x", padx=20, pady=(0, 10))

        self.entry_password = ctk.CTkEntry(
            input_row,
            placeholder_text="Type password to evaluate...",
            show="*",
            height=38,
            font=ctk.CTkFont(size=13),
        )
        self.entry_password.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.entry_password.bind("<Return>", lambda e: self._check_password())

        self.btn_toggle_eye = ctk.CTkButton(
            input_row,
            text="Show",
            width=70,
            height=38,
            fg_color=BTN_SECONDARY_FG,
            hover_color=BTN_SECONDARY_HOVER,
            border_color=BTN_SECONDARY_BORDER,
            border_width=1,
            text_color=TEXT_PRIMARY,
            command=self._toggle_visibility,
        )
        self.btn_toggle_eye.pack(side="left", padx=(0, 8))

        self.btn_check = ctk.CTkButton(
            input_row,
            text="Evaluate",
            width=110,
            height=38,
            fg_color=PRIMARY,
            hover_color=PRIMARY_HOVER,
            font=ctk.CTkFont(weight="bold"),
            command=self._check_password,
        )
        self.btn_check.pack(side="left", padx=(0, 8))

        self.btn_reset = ctk.CTkButton(
            input_row,
            text="Clear",
            width=65,
            height=38,
            fg_color=BTN_SECONDARY_FG,
            hover_color=BTN_SECONDARY_HOVER,
            border_color=BTN_SECONDARY_BORDER,
            border_width=1,
            text_color=TEXT_PRIMARY,
            command=self._reset_fields,
        )
        self.btn_reset.pack(side="left")

        # Results Container (Cards)
        self.results_container = ctk.CTkFrame(scroll, fg_color="transparent")
        self.results_container.pack(fill="both", expand=True)

        self._build_results_panels(self.results_container)

    def _build_results_panels(self, parent: ctk.CTkFrame) -> None:
        # 1. Quick Verdict Banner Card
        self.card_verdict = ctk.CTkFrame(
            parent,
            fg_color=BG_CARD,
            corner_radius=8,
            border_width=1,
            border_color=BORDER_COLOR,
        )
        self.card_verdict.pack(fill="x", pady=(0, 14), ipady=6)

        self.lbl_verdict_title = ctk.CTkLabel(
            self.card_verdict,
            text="Verdict: Awaiting Input",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=TEXT_SECONDARY,
        )
        self.lbl_verdict_title.pack(anchor="w", padx=20, pady=(10, 2))

        self.lbl_verdict_desc = ctk.CTkLabel(
            self.card_verdict,
            text="Enter a candidate password above to perform security assessment.",
            font=ctk.CTkFont(size=12),
            text_color=TEXT_SECONDARY,
            wraplength=700,
            justify="left",
        )
        self.lbl_verdict_desc.pack(anchor="w", padx=20, pady=(0, 10))

        # 2. Strength & Metrics Card
        metrics_card = ctk.CTkFrame(
            parent,
            fg_color=BG_CARD,
            corner_radius=8,
            border_width=1,
            border_color=BORDER_COLOR,
        )
        metrics_card.pack(fill="x", pady=(0, 14), ipady=8)

        ctk.CTkLabel(
            metrics_card,
            text="Strength & Entropy Analysis",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=PRIMARY,
        ).pack(anchor="w", padx=20, pady=(14, 8))

        score_row = ctk.CTkFrame(metrics_card, fg_color="transparent")
        score_row.pack(fill="x", padx=20, pady=(0, 8))

        ctk.CTkLabel(
            score_row,
            text="Calculated Strength Score:",
            font=ctk.CTkFont(size=12),
            text_color=TEXT_SECONDARY,
        ).pack(side="left")
        self.lbl_score_val = ctk.CTkLabel(
            score_row,
            text="0 / 100",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=TEXT_PRIMARY,
        )
        self.lbl_score_val.pack(side="left", padx=(8, 16))

        self.lbl_strength_badge = ctk.CTkLabel(
            score_row,
            text="[NOT EVALUATED]",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=TEXT_SECONDARY,
        )
        self.lbl_strength_badge.pack(side="left")

        # Progress bar strength meter
        self.strength_meter = ctk.CTkProgressBar(metrics_card, height=10, corner_radius=5)
        self.strength_meter.pack(fill="x", padx=20, pady=(0, 14))
        self.strength_meter.set(0)
        self.strength_meter.configure(progress_color=PRIMARY)

        # 3. Two columns: Feedback / Suggestions & Policy Rules
        grid_frame = ctk.CTkFrame(parent, fg_color="transparent")
        grid_frame.pack(fill="x", pady=(0, 14))
        grid_frame.grid_columnconfigure((0, 1), weight=1, uniform="feedback_grid")

        # Feedback Card (Left)
        self.feedback_card = ctk.CTkFrame(
            grid_frame,
            fg_color=BG_CARD,
            corner_radius=8,
            border_width=1,
            border_color=BORDER_COLOR,
        )
        self.feedback_card.grid(row=0, column=0, padx=(0, 6), sticky="nsew", ipady=8)

        ctk.CTkLabel(
            self.feedback_card,
            text="Security Observations",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=PRIMARY,
        ).pack(anchor="w", padx=20, pady=(14, 8))

        self.lbl_feedback_text = ctk.CTkLabel(
            self.feedback_card,
            text="No observations yet.",
            font=ctk.CTkFont(size=12),
            text_color=TEXT_SECONDARY,
            justify="left",
            wraplength=340,
        )
        self.lbl_feedback_text.pack(anchor="w", padx=20, pady=(0, 14))

        # Policy Card (Right)
        self.policy_card = ctk.CTkFrame(
            grid_frame,
            fg_color=BG_CARD,
            corner_radius=8,
            border_width=1,
            border_color=BORDER_COLOR,
        )
        self.policy_card.grid(row=0, column=1, padx=(6, 0), sticky="nsew", ipady=8)

        ctk.CTkLabel(
            self.policy_card,
            text="Policy Compliance",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=PRIMARY,
        ).pack(anchor="w", padx=20, pady=(14, 8))

        self.lbl_policy_text = ctk.CTkLabel(
            self.policy_card,
            text="No policy rules evaluated yet.",
            font=ctk.CTkFont(size=12),
            text_color=TEXT_SECONDARY,
            justify="left",
            wraplength=340,
        )
        self.lbl_policy_text.pack(anchor="w", padx=20, pady=(0, 14))

    def _toggle_visibility(self) -> None:
        self.is_password_visible = not self.is_password_visible
        if self.is_password_visible:
            self.entry_password.configure(show="")
            self.btn_toggle_eye.configure(text="Hide")
        else:
            self.entry_password.configure(show="*")
            self.btn_toggle_eye.configure(text="Show")

    def _reset_fields(self) -> None:
        self.entry_password.delete(0, "end")
        self.lbl_verdict_title.configure(text="Verdict: Awaiting Input", text_color=TEXT_SECONDARY)
        self.lbl_verdict_desc.configure(text="Enter a candidate password above to perform security assessment.")
        self.lbl_score_val.configure(text="0 / 100")
        self.lbl_strength_badge.configure(text="[NOT EVALUATED]", text_color=TEXT_SECONDARY)
        self.strength_meter.set(0)
        self.strength_meter.configure(progress_color=PRIMARY)
        self.lbl_feedback_text.configure(text="No observations yet.")
        self.lbl_policy_text.configure(text="No policy rules evaluated yet.")

    def _check_password(self) -> None:
        candidate = self.entry_password.get()
        if not candidate:
            self._reset_fields()
            return

        # 1. Dictionary Check
        is_in_dict = check_dictionary(candidate, self.dict_manager)

        # 2. Strength Evaluation
        strength = evaluate_strength(candidate, self.dict_manager)

        # 3. Policy Evaluation
        policy_res = self.policy.evaluate(candidate)

        # Update Verdict Banner
        if is_in_dict:
            self.lbl_verdict_title.configure(
                text="Unsafe: Found in Common Password Dictionary",
                text_color=DANGER,
            )
            self.lbl_verdict_desc.configure(
                text="This exact password appears in common leaked password wordlists. "
                "Automated dictionary attacks will crack this credential near instantaneously."
            )
        elif strength.level in (StrengthLevel.VERY_WEAK, StrengthLevel.WEAK):
            self.lbl_verdict_title.configure(
                text="Weak: Vulnerable to Pattern & Brute-Force Cracking",
                text_color=DANGER,
            )
            self.lbl_verdict_desc.configure(
                text="Although not matched in the current dictionary, this password has low structural complexity, "
                "repetition, or short length."
            )
        elif strength.level == StrengthLevel.MODERATE:
            self.lbl_verdict_title.configure(
                text="Moderate: Acceptable Baseline Complexity",
                text_color=WARNING,
            )
            self.lbl_verdict_desc.configure(
                text="Meets baseline requirements but could be strengthened with increased length and greater character diversity."
            )
        else:
            self.lbl_verdict_title.configure(
                text="Strong: Robust Against Dictionary Attacks",
                text_color=SUCCESS,
            )
            self.lbl_verdict_desc.configure(
                text="This credential exhibits high entropy, meets complexity standards, and was not found in dictionary sets."
            )

        # Update Score and Meter
        score = strength.score
        self.lbl_score_val.configure(text=f"{score} / 100")

        meter_val = score / 100.0
        self.strength_meter.set(meter_val)

        level_name = strength.level.value.replace("_", " ")
        if score < 30:
            meter_color = DANGER
        elif score < 60:
            meter_color = WARNING
        elif score < 85:
            meter_color = PRIMARY
        else:
            meter_color = SUCCESS

        self.strength_meter.configure(progress_color=meter_color)
        self.lbl_strength_badge.configure(text=f"[{level_name}]", text_color=meter_color)

        # Update Feedback
        if strength.feedback:
            feedback_str = "\n".join(f"• {f}" for f in strength.feedback)
        else:
            feedback_str = "• Meets entropy and length thresholds."
        self.lbl_feedback_text.configure(text=feedback_str)

        # Update Policy Compliance
        policy_lines = [
            f"Compliance: {policy_res.passed_count}/{policy_res.total_rules} rules satisfied ({policy_res.compliance_percentage:.0f}%)\n"
        ]
        for r in policy_res.rules:
            icon = "[PASS]" if r.passed else "[FAIL]"
            policy_lines.append(f"{icon} {r.name}")

        self.lbl_policy_text.configure(text="\n".join(policy_lines))
