"""
CAPSS - Context-Aware Privacy Protection and Scheme Selection

File:
    duplicate_detector.py

Purpose
-------
Detect duplicate, repeated and replay-like
registration behaviour.

This detector performs lightweight behavioural
analysis before the AMF.

NOTE
----
Replay detection is metadata-based and not
protocol-level replay detection.
"""

from systems.pre_amf.attack_rules import (
    ATTACK_DUPLICATE,
    ATTACK_REPLAY,
    ATTACK_NONE,
    DUPLICATE_INTERVAL,
    REPLAY_INTERVAL,
    LOW_CONFIDENCE,
    MEDIUM_CONFIDENCE,
    HIGH_CONFIDENCE,
    NORMAL,
    SUSPICIOUS,
    MALICIOUS,
    MESSAGE_DUPLICATE,
    MESSAGE_REPLAY,
)

from systems.pre_amf.models import (
    ValidationContext,
    DetectionResult,
)


class DuplicateDetector:
    """
    Detect duplicate and replay-like
    registration behaviour.
    """

    def detect(
        self,
        context: ValidationContext,
    ) -> DetectionResult:

        request = context.request
        history = context.history

        # ==================================================
        # First Registration
        # ==================================================

        if history.registration_count == 0:

            return DetectionResult(

                detected=False,

                attack_type=ATTACK_NONE,

                confidence=LOW_CONFIDENCE,

                severity=NORMAL,

                score=0,

                message="First registration.",

                current_rate=0.0,

                peak_rate=0.0,

                current_count=1,

                window_seconds=0

            )

        # ==================================================
        # Previous Registration
        # ==================================================

        previous_time = history.last_seen
        previous_suci = history.last_suci

        interval = request.timestamp - previous_time
        print(
                f"[DuplicateDetector] "
                f"UE={request.ue_id} "
                f"prev={previous_time} "
                f"curr={request.timestamp} "
                f"interval={interval.total_seconds():.1f}s "
                f"count={history.registration_count}"
            )

        # ==================================================
        # Replay-like Behaviour
        # ==================================================

        if (
            interval <= REPLAY_INTERVAL
            and
            request.authentication_result == "Success"
            and
            request.suci == previous_suci
        ):

            history.replay_count += 1
            history.last_attack = ATTACK_REPLAY

            replay_events = history.replay_count

            score = round(
                min((replay_events / 5.0) * 100, 100),
                2
            )

            confidence = round(
                min(0.50 + (replay_events * 0.10), 1.0),
                2
            )

            if score >= 80:
                severity = MALICIOUS
            else:
                severity = SUSPICIOUS

            return DetectionResult(

                detected=True,

                attack_type=ATTACK_REPLAY,

                confidence=confidence,

                severity=severity,

                score=score,

                message=MESSAGE_REPLAY,

                current_rate=0.0,

                peak_rate=0.0,

                current_count=history.registration_count,

                window_seconds=0

            )

        # ==================================================
        # Duplicate Registration
        # ==================================================

        if interval <= DUPLICATE_INTERVAL:

            history.duplicate_count += 1
            history.last_attack = ATTACK_DUPLICATE

            duplicate_events = history.duplicate_count

            score = round(
                min((duplicate_events / 5.0) * 100, 100),
                2
            )

            confidence = round(
                min(0.40 + (duplicate_events * 0.12), 1.0),
                2
            )

            if score >= 80:
                severity = MALICIOUS
            else:
                severity = SUSPICIOUS

            return DetectionResult(

                detected=True,

                attack_type=ATTACK_DUPLICATE,

                confidence=confidence,

                severity=severity,

                score=score,

                message=MESSAGE_DUPLICATE,

                current_rate=0.0,

                peak_rate=0.0,

                current_count=history.registration_count,

                window_seconds=0

            )

        # ==================================================
        # Normal Behaviour
        # ==================================================

        history.last_attack = ATTACK_NONE

        return DetectionResult(

            detected=False,

            attack_type=ATTACK_NONE,

            confidence=LOW_CONFIDENCE,

            severity=NORMAL,

            score=0,

            message="Registration interval normal.",

            current_rate=0.0,

            peak_rate=0.0,

            current_count=history.registration_count,

            window_seconds=0

        )


# ==========================================================
# Convenience Function
# ==========================================================

def detect_duplicate(
    context: ValidationContext,
) -> DetectionResult:
    """
    Convenience wrapper.
    """

    detector = DuplicateDetector()

    return detector.detect(context)