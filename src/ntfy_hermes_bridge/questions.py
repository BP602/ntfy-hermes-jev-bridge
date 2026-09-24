"""Versioned Jev question set. Changing any text here requires a new version and a corpus replay."""

QUESTION_SET_VERSION = "ops-notification-v1"

CATEGORY_CRITERIA = {
    "security": "Compromise, unauthorized access, credential, malware, or security-control failure",
    "data_integrity": "Data loss, corruption, backup failure, restore failure, or storage degradation",
    "availability": "A service, dependency, or network path is unavailable or repeatedly failing",
    "capacity": "Storage, memory, CPU, quota, certificate, or resource exhaustion risk",
    "actionable_change": "A watched external condition changed in a way the operator may act on",
    "maintenance": "Planned maintenance, update, restart, or lifecycle information",
    "recovery": "A previously unhealthy condition recovered",
    "routine_success": "Expected successful completion or healthy heartbeat",
    "informational": "Information with no clear action or risk",
    "other": "None of the above",
}

CATEGORIES = tuple(CATEGORY_CRITERIA)

NOUL_QUESTIONS = (
    "immediate_harm_if_ignored",
    "human_action_useful",
    "digest_value",
    "routine_noise",
    "personal_relevance",
)

QUESTIONS: dict[str, dict] = {
    "category": {
        "type": "choice",
        "instructions": "Classify the primary operational meaning of this notification.",
        "criteria": CATEGORY_CRITERIA,
    },
    "immediate_harm_if_ignored": {
        "type": "noul",
        "instructions": (
            "Would waiting until the next digest plausibly increase security, data-loss, outage, "
            "financial, or safety impact?"
        ),
        "criteria": {
            "true": "Delay can materially worsen impact or remove a useful response window",
            "false": "Delay until the next digest is unlikely to worsen impact",
        },
    },
    "human_action_useful": {
        "type": "noul",
        "instructions": "Does this notification contain a condition for which the operator can take a useful action?",
    },
    "digest_value": {
        "type": "noul",
        "instructions": (
            "Even if it should not interrupt now, would retaining this event in a concise daily digest "
            "help the operator understand or manage the system?"
        ),
    },
    "routine_noise": {
        "type": "noul",
        "instructions": (
            "Is this an expected routine success, heartbeat, duplicate status, or low-value informational "
            "event that can be omitted without reducing operational awareness?"
        ),
    },
    "personal_relevance": {
        "type": "noul",
        "instructions": "Given `user_policy`, is this event relevant to the operator's stated interests or responsibilities?",
    },
}
