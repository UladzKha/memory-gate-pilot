"""Per-note memory-write defenses. Classifier weights load on first check."""

from abc import ABC, abstractmethod
from collections.abc import Callable
from importlib import import_module
from typing import Literal


Decision = Literal["allow", "quarantine", "block"]
MALICIOUS_CLASS_INDEX = 1


class Defense(ABC):
    name: str

    @abstractmethod
    def check(self, note: str) -> Decision:
        """Return the fate of one proposed memory note."""


class NoDefense(Defense):
    name = "no_defense"

    def check(self, note: str) -> Decision:
        return "allow"


class _ClassifierDefense(Defense):
    """Shared threshold policy for the two sequence classifiers."""

    def __init__(
        self, model_id: str, threshold: float = 0.5,
        score_fn: Callable[[str], float] | None = None,
    ) -> None:
        if not 0 <= threshold <= 1:
            raise ValueError("Classifier threshold must be between 0 and 1")
        self.model_id = model_id
        self.threshold = threshold
        self._score_fn = score_fn
        self._tokenizer = None
        self._model = None
        self._device = None

    def _load(self) -> None:
        # Imports and cache reads happen only when check() needs a real score.
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        tokenizer = AutoTokenizer.from_pretrained(self.model_id, local_files_only=True)
        model = AutoModelForSequenceClassification.from_pretrained(
            self.model_id, local_files_only=True
        )
        if model.config.num_labels != 2:
            raise ValueError(f"Expected two classifier labels for {self.model_id}")
        label = model.config.id2label[MALICIOUS_CLASS_INDEX].lower()
        if label not in ("malicious", "injection", "label_1"):
            raise ValueError(f"Unexpected malicious label for {self.model_id}: {label}")
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self._tokenizer = tokenizer
        self._model = model.to(device).eval()
        self._device = device

    def _score(self, note: str) -> float:
        if self._model is None:
            self._load()
        import torch

        # Each note is usually short; overflow chunks keep long notes visible.
        inputs = self._tokenizer(
            note, return_tensors="pt", truncation=True, max_length=512,
            return_overflowing_tokens=True, padding=True,
        )
        inputs.pop("overflow_to_sample_mapping", None)
        inputs = {key: value.to(self._device) for key, value in inputs.items()}
        with torch.inference_mode():
            probabilities = self._model(**inputs).logits.softmax(dim=-1)
        return float(probabilities[:, MALICIOUS_CLASS_INDEX].max().item())

    def check(self, note: str) -> Decision:
        score = self._score_fn(note) if self._score_fn is not None else self._score(note)
        if not 0 <= score <= 1:
            raise ValueError(f"Invalid malicious score: {score}")
        return "block" if score >= self.threshold else "allow"


class PromptGuard(_ClassifierDefense):
    name = "prompt_guard"

    def __init__(
        self, model_id: str = "meta-llama/Llama-Prompt-Guard-2-86M",
        threshold: float = 0.5,
        score_fn: Callable[[str], float] | None = None,
    ) -> None:
        super().__init__(model_id, threshold, score_fn)


class ProtectAIDeberta(_ClassifierDefense):
    name = "protectai_deberta"

    def __init__(
        self, model_id: str = "protectai/deberta-v3-base-prompt-injection-v2",
        threshold: float = 0.5,
        score_fn: Callable[[str], float] | None = None,
    ) -> None:
        super().__init__(model_id, threshold, score_fn)


class GateAdapter(Defense):
    name = "gate"

    def __init__(self, import_path: str | None) -> None:
        self.import_path = import_path
        self._gate = None

    def check(self, note: str) -> Decision:
        if not self.import_path:
            raise NotImplementedError("Set defenses.gate.import_path to the real gate")
        if self._gate is None:
            module_name, separator, object_name = self.import_path.partition(":")
            if not separator or not module_name or not object_name:
                raise ValueError("Gate import path must be module:ClassOrObject")
            gate_object = getattr(import_module(module_name), object_name)
            self._gate = gate_object() if isinstance(gate_object, type) else gate_object
            if not callable(getattr(self._gate, "check", None)):
                raise TypeError("Imported gate must provide check(note)")
        decision = self._gate.check(note, None, "")
        outcome = getattr(decision, "outcome", decision)
        if outcome not in ("allow", "allow_tainted", "block"):
            raise ValueError(f"Real gate returned invalid decision: {decision!r}")
        return outcome

    def check_batch(self, notes: list[str], inbox: list[dict], owner: str) -> list:
        if self._gate is None:
            self.check("")
        decisions = self._gate.check_batch(notes, inbox, owner)
        if len(decisions) != len(notes) or any(
            decision.outcome not in ("allow", "allow_tainted", "block") for decision in decisions
        ):
            raise ValueError("Real gate returned invalid batch decisions")
        return decisions

    def memory_entries(self, notes: list[str], inbox: list[dict], owner: str) -> list:
        if self._gate is None:
            self.check("")
        from memgate import write_memory
        return write_memory(notes, inbox, owner)


def build_defense(name: str, config: dict) -> Defense:
    settings = config["defenses"]
    if name == "no_defense":
        return NoDefense()
    if name == "prompt_guard":
        return PromptGuard(**settings[name])
    if name == "protectai_deberta":
        return ProtectAIDeberta(**settings[name])
    if name == "gate":
        return GateAdapter(**settings[name])
    raise ValueError(f"Unknown defense condition: {name}")
