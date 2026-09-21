"""CLI for converting CICFlowMeter/CICIDS CSVs to the project schema."""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from src.features.unidirectional_features import transform_dataframe


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert CICIDS flow CSV to unidirectional features")
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    df = pd.read_csv(args.input)
    result = transform_dataframe(df)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    result.to_csv(args.output, index=False)
    print(f"Converted {len(result):,} rows")
    print(f"Features: {len([c for c in result.columns if c not in {'Label', 'label'}])}")
    print(f"Output: {args.output}")


if __name__ == "__main__":
    main()
