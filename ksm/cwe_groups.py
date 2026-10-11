"""CWE groups definition and classification for Vulnerability Atlas."""

from typing import Optional, Union

CWE_GROUPS_TABLE = {
    "Memory safety": {
        119, 120, 121, 122, 125, 126, 127, 131, 190, 191, 193, 415, 416, 476,
        680, 681, 786, 787, 788, 805, 822, 823, 824, 825, 908, 909,
    },
    "Resource management": {
        400, 401, 404, 674, 770, 772, 789, 834, 835,
    },
    "Concurrency": {
        362, 366, 367, 413, 667,
    },
    "Injection": {
        74, 77, 78, 79, 88, 89, 91, 93, 94, 113,
    },
    "Input validation and paths": {
        20, 22, 23, 59, 61, 73, 129, 436, 444, 1284,
    },
    "Access control and crypto": {
        250, 269, 276, 284, 285, 287, 290, 294, 295, 297, 306, 310, 311, 312,
        319, 326, 327, 328, 330, 338, 345, 347, 352, 354, 384, 522, 639, 732,
        862, 863,
    },
    "Information exposure": {
        200, 201, 203, 208, 209, 532,
    },
    "Logic and numeric errors": {
        369, 617, 670, 682, 697, 704, 754, 755, 843, 1335,
    },
}

GROUP_NAMES = [
    "Memory safety",
    "Resource management",
    "Concurrency",
    "Injection",
    "Input validation and paths",
    "Access control and crypto",
    "Information exposure",
    "Logic and numeric errors",
    "Other",
    "Unknown",
]

_CWE_TO_GROUP = {
    cwe: grp
    for grp, cwes in CWE_GROUPS_TABLE.items()
    for cwe in cwes
}


def get_cwe_group(cwe_id: Optional[Union[str, int]]) -> str:
    """Return the CWE group name for a given CWE ID.

    Returns:
        "Unknown" if cwe_id is None, empty, or "UNKNOWN".
        The group name if the numerical ID is in CWE_GROUPS_TABLE.
        "Other" for any other stated CWE ID.
    """
    if not cwe_id or cwe_id == "UNKNOWN":
        return "Unknown"
    if isinstance(cwe_id, int):
        num = cwe_id
    else:
        num_str = str(cwe_id).strip()
        if num_str.startswith("CWE-"):
            num_str = num_str[4:]
        try:
            num = int(num_str)
        except ValueError:
            return "Other"
    return _CWE_TO_GROUP.get(num, "Other")


def group_to_slug(group_name: str) -> str:
    """Return a lowercase hyphen-separated slug for a group name."""
    return group_name.lower().replace(" ", "-")
