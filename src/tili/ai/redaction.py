
"""Privacy-preserving redaction for TILI AI evidence.

Original log events must never be modified. This module creates a separate
redacted representation for local AI processing.
"""

import re


class EvidenceRedactor:
    """Redact secrets and pseudonymise sensitive identifiers consistently."""

    def __init__(self):
        self._identifier_map = {}
        self._counters = {}

    def _replacement(self, category, value):
        """Return a stable pseudonym for the same value within this package."""

        key = (category, value)

        if key not in self._identifier_map:
            number = self._counters.get(category, 0) + 1
            self._counters[category] = number
            self._identifier_map[key] = f"[{category}_{number:03d}]"

        return self._identifier_map[key]

    def redact_text(self, text):
        """Return redacted text without changing the original input."""

        if not isinstance(text, str):
            raise TypeError("Evidence text must be a string.")

        result = text

        # Remove complete PEM private-key blocks.
        result = re.sub(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?"
            r"-----END [A-Z0-9 ]*PRIVATE KEY-----",
            "[REDACTED_PRIVATE_KEY]",
            result,
            flags=re.I | re.S,
        )

        # Redact HTTP authentication credentials.
        result = re.sub(
            r"\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+",
            r"\1 [REDACTED]",
            result,
            flags=re.I,
        )

        # Redact common secret-bearing fields in JSON.
        json_secret_pattern = re.compile(
            r'(["\'](?:password|passwd|pwd|token|access_token|'
            r'refresh_token|client_secret|api_key|apikey|secret|'
            r'private_key|authorization|cookie|set-cookie)["\']'
            r'\s*:\s*)(["\'])(.*?)\2',
            re.I,
        )

        result = json_secret_pattern.sub(
            lambda m: (
                f"{m.group(1)}{m.group(2)}"
                f"[REDACTED]{m.group(2)}"
            ),
            result,
        )

        # Redact common secret-bearing fields in plain-text logs.
        secret_pattern = re.compile(
            r"\b(password|passwd|pwd|token|access_token|refresh_token|"
            r"client_secret|api_key|apikey|secret|private_key|"
            r"authorization|cookie|set-cookie)\b"
            r"(\s*[=:]\s*)([^\s,;]+)",
            re.I,
        )

        result = secret_pattern.sub(
            lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]",
            result,
        ) 

       
        # Pseudonymise explicitly labelled JSON infrastructure identifiers.
        json_identifier_pattern = re.compile(
            r'(["\'])(device_uid|device_id|konnektor_id|hardware_id|'
            r'serial_number|serial_no|seriennummer|hostname|host_name|'
            r'instance_id)\1\s*:\s*(["\'])(.*?)\3',
            re.I,
        )

        def replace_json_identifier(match):
            label = match.group(2).upper()
            value = match.group(4)

            if re.fullmatch(r"cHSM-[0-9]{1,4}", value, re.I):
                replacement = value
            else:
                replacement = self._replacement(label, value)

            return (
                f"{match.group(1)}{match.group(2)}{match.group(1)}: "
                f"{match.group(3)}{replacement}{match.group(3)}"
            )

        result = json_identifier_pattern.sub(
            replace_json_identifier, result
        )

        # Pseudonymise explicitly labelled infrastructure identifiers.
        identifier_pattern = re.compile(
            r"\b(device_uid|device_id|konnektor_id|hardware_id|"
            r"serial_number|serial_no|seriennummer|hostname|host_name|"
            r"instance_id)\b"
            r"(\s*[=:]\s*)"
            r'["\']?([A-Za-z0-9_.:/-]{2,100})',
            re.I,
        )

        def replace_identifier(match):
            label = match.group(1).upper()
            value = match.group(3)

            # Preserve the established cHSM instance representation.
            if re.fullmatch(r"cHSM-[0-9]{1,4}", value, re.I):
                replacement = value
            else:
                replacement = self._replacement(label, value)

            return f"{match.group(1)}{match.group(2)}{replacement}"

        result = identifier_pattern.sub(replace_identifier, result)

        # Pseudonymise standalone UUIDs.
        def replace_uuid(match):
            return self._replacement("UUID", match.group(0).lower())

        result = re.sub(
            r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{4}-[0-9a-f]{12}\b",
            replace_uuid,
            result,
            flags=re.I,
        )

        # Pseudonymise email addresses.
        def replace_email(match):
            return self._replacement("EMAIL", match.group(0).lower())

        result = re.sub(
            r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
            replace_email,
            result,
            flags=re.I,
        )

        return result
	
    def redact_metadata(self, metadata):
        """Return a redacted copy of evidence metadata."""

        if not isinstance(metadata, dict):
            raise TypeError("Evidence metadata must be a dictionary.")

        result = metadata.copy()

        identifier_fields = {
            "hostname",
            "host_name",
            "device_uid",
            "device_id",
            "konnektor_id",
            "hardware_id",
            "serial_number",
            "serial_no",
            "seriennummer",
        }

        for field in identifier_fields:
            value = result.get(field)

            if isinstance(value, str) and value:
                result[field] = self._replacement(
                    field.upper(), value
                )

        # Preserve the established cHSM instance representation.
        instance_id = result.get("instance_id")

        if isinstance(instance_id, str) and instance_id:
            if not re.fullmatch(r"cHSM-[0-9]{1,4}", instance_id, re.I):
                result["instance_id"] = self._replacement(
                    "INSTANCE_ID", instance_id
                )

        # Hide sensitive filenames while preserving their extension.
        file_name = result.get("file_name")

        if isinstance(file_name, str) and file_name:
            file_name = file_name.replace("\\", "/").rsplit("/", 1)[-1]
            extension = ""

            if "." in file_name:
                extension = "." + file_name.rsplit(".", 1)[-1]

            result["file_name"] = (
                self._replacement("FILE", file_name) + extension
            )

        return result


    def redact_secrets(self, text):
        """Mask secrets while preserving infrastructure identifiers."""

        if not isinstance(text, str):
            raise TypeError("Evidence text must be a string.")

        result = text

        # Remove complete PEM private-key blocks.
        result = re.sub(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?"
            r"-----END [A-Z0-9 ]*PRIVATE KEY-----",
            "[REDACTED_PRIVATE_KEY]",
            result,
            flags=re.I | re.S,
        )

        # Redact HTTP authentication credentials.
        result = re.sub(
            r"\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+",
            r"\1 [REDACTED]",
            result,
            flags=re.I,
        )

        # Redact secret-bearing JSON fields.
        json_secret_pattern = re.compile(
            r'(["\'](?:password|passwd|pwd|token|access_token|'
            r'refresh_token|client_secret|api_key|apikey|secret|'
            r'private_key|authorization|cookie|set-cookie)["\']'
            r'\s*:\s*)(["\'])(.*?)\2',
            re.I,
        )

        result = json_secret_pattern.sub(
            lambda m: (
                f"{m.group(1)}{m.group(2)}"
                f"[REDACTED]{m.group(2)}"
            ),
            result,
        )

        # Redact secret-bearing plain-text fields.
        secret_pattern = re.compile(
            r"\b(password|passwd|pwd|token|access_token|refresh_token|"
            r"client_secret|api_key|apikey|secret|private_key|"
            r"authorization|cookie|set-cookie)\b"
            r"(\s*[=:]\s*)([^\s,;]+)",
            re.I,
        )

        result = secret_pattern.sub(
            lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]",
            result,
        )

        return result
