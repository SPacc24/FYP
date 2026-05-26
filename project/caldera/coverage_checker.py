import logging
from typing import Any
from caldera.api_client import CalderaAPIError, CalderaClient

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


class CoverageChecker:
    """
    Checks CALDERA ability coverage for MITRE ATT&CK techniques.
    """

    def __init__(self, caldera_client: CalderaClient):
        self.client = caldera_client
        self._ability_cache = None
        self._technique_to_abilities = {}

    def _load_abilities(self) -> list[dict]:
        """
        Fetch and cache all abilities from Caldera.
        Handles both full list and filtered endpoints.
        """
        if self._ability_cache is not None:
            return self._ability_cache

        try:
            abilities_result = self.client.get_abilities()
            
            if isinstance(abilities_result, dict):
                abilities = abilities_result.get("abilities", [])
            else:
                abilities = abilities_result or []

            self._ability_cache = abilities
            log.info(f"Loaded {len(abilities)} abilities from CALDERA")
            return abilities

        except CalderaAPIError as e:
            log.error(f"Failed to load abilities: {e}")
            return []

    def _build_technique_map(self) -> dict[str, list[dict]]:
        """
        Build a mapping of technique IDs to their matching abilities.
        Handles various ability/technique ID formats.
        """
        if self._technique_to_abilities:
            return self._technique_to_abilities

        abilities = self._load_abilities()

        for ability in abilities:
            technique_id = ability.get("technique_id") or ability.get("technique")

            if not technique_id:
                continue

            # Normalize: some abilities store technique as nested dict
            if isinstance(technique_id, dict):
                technique_id = technique_id.get("attack_id")

            if not technique_id:
                continue

            technique_id = str(technique_id).strip().upper()

            if technique_id not in self._technique_to_abilities:
                self._technique_to_abilities[technique_id] = []

            self._technique_to_abilities[technique_id].append({
                "ability_id": ability.get("ability_id"),
                "ability_name": ability.get("name"),
                "platforms": ability.get("platforms", {}),
                "tactic": ability.get("tactic"),
            })

        return self._technique_to_abilities

    def check_technique_coverage(
        self,
        technique_ids: list[str]
    ) -> dict[str, Any]:
        """
        Check which techniques have CALDERA ability support.

        Returns:
        {
            "total": 5,
            "supported": 3,
            "unsupported": 2,
            "techniques": {
                "T1046": {
                    "supported": True,
                    "ability_count": 2,
                    "abilities": [
                        {"ability_id": "...", "ability_name": "...", "platforms": {...}},
                    ]
                },
                "T1110": {
                    "supported": False,
                    "ability_count": 0,
                    "abilities": []
                }
            }
        }
        """
        if not technique_ids:
            return {
                "total": 0,
                "supported": 0,
                "unsupported": 0,
                "techniques": {},
            }

        technique_map = self._build_technique_map()
        result_techniques = {}
        supported_count = 0
        unsupported_count = 0

        for tid in technique_ids:
            tid_normalized = str(tid).strip().upper()
            matching_abilities = technique_map.get(tid_normalized, [])

            is_supported = len(matching_abilities) > 0

            if is_supported:
                supported_count += 1
            else:
                unsupported_count += 1

            result_techniques[tid_normalized] = {
                "supported": is_supported,
                "ability_count": len(matching_abilities),
                "abilities": matching_abilities,
            }

            if is_supported:
                log.info(
                    f"Technique {tid_normalized} is supported by {len(matching_abilities)} ability/ies"
                )
            else:
                log.warning(f"Technique {tid_normalized} has no matching abilities in CALDERA")

        return {
            "total": len(technique_ids),
            "supported": supported_count,
            "unsupported": unsupported_count,
            "techniques": result_techniques,
        }

    def get_supported_techniques(self, technique_ids: list[str]) -> list[str]:
        """
        Filter list to only return supported techniques.
        """
        coverage = self.check_technique_coverage(technique_ids)
        supported = []

        for tid, info in coverage.get("techniques", {}).items():
            if info.get("supported"):
                supported.append(tid)

        return supported

    def clear_cache(self) -> None:
        """
        Clear internal ability cache to force refresh on next check.
        """
        self._ability_cache = None
        self._technique_to_abilities = {}
        log.info("Coverage checker cache cleared")