"""Harness entry point. Dataset integrity is checked before any other work."""

from .dataset import verify_dataset


def main() -> None:
    verify_dataset()
    print("Dataset SHA-256 verification passed for all three final sets.")


if __name__ == "__main__":
    main()
