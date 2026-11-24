
"""Local Ollama provider for TILI AI diagnostics.

This module communicates only with the configured local Ollama endpoint.
Evidence preparation and redaction must happen before prompts reach this
provider.
"""

import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class AIProviderError(RuntimeError):
    """Base exception for AI provider errors."""


class AIProviderNotConfigured(AIProviderError):
    """Raised when AI assistance is not configured."""


class OllamaProvider:
    """Generate text using a locally running Ollama model."""

    def __init__(
        self,
        base_url="http://127.0.0.1:11434",
        model="qwen2.5:3b",
        timeout=180,
    ):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    def generate(self, prompt, system=None, options=None):
        """Generate a non-streaming response from the local model."""

        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError("Prompt must be a non-empty string.")

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
        }

        if system:
            payload["system"] = system

        if options:
            payload["options"] = options

        request = Request(
            f"{self.base_url}/api/generate",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urlopen(request, timeout=self.timeout) as response:
                result = json.loads(response.read().decode("utf-8"))

        except HTTPError as exc:
            raise AIProviderError(
                f"Ollama returned HTTP {exc.code}."
            ) from exc

        except URLError as exc:
            raise AIProviderError(
                f"Cannot connect to local Ollama: {exc.reason}"
            ) from exc

        except TimeoutError as exc:
            raise AIProviderError(
                f"Ollama request timed out after {self.timeout} seconds."
            ) from exc

        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise AIProviderError(
                "Ollama returned an invalid response."
            ) from exc

        generated_text = result.get("response")

        if not isinstance(generated_text, str) or not generated_text.strip():
            raise AIProviderError(
                "Ollama returned an empty or invalid generation."
            )

        return generated_text.strip()


class AIProvider:
    """Compatibility placeholder for the future diagnostic pipeline."""

    def explain_findings(self, findings, approved_context=None):
        raise AIProviderNotConfigured(
            "The diagnostic pipeline is not connected yet. "
            "Evidence preparation and redaction must be implemented first."
        )

