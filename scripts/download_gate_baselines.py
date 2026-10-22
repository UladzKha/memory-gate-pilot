"""Cache the two classifier weight sets used by DEV gate comparisons."""

from huggingface_hub import snapshot_download
from huggingface_hub.errors import GatedRepoError, HfHubHTTPError, RepositoryNotFoundError


FILES = ["config.json", "model.safetensors", "tokenizer.json",
         "tokenizer_config.json", "special_tokens_map.json", "added_tokens.json", "spm.model"]


def main() -> None:
    protectai = "protectai/deberta-v3-base-prompt-injection-v2"
    path = snapshot_download(protectai, allow_patterns=FILES)
    print(f"cached {protectai}: {path}")

    promptguard = "meta-llama/Llama-Prompt-Guard-2-86M"
    try:
        path = snapshot_download(promptguard, allow_patterns=FILES)
    except (GatedRepoError, RepositoryNotFoundError, HfHubHTTPError) as error:
        print(f"{promptguard} unavailable to this Hugging Face account: {type(error).__name__}")
    else:
        print(f"cached {promptguard}: {path}")


if __name__ == "__main__":
    main()
