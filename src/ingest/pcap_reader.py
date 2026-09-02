import pandas as pd
from pathlib import Path


def read_zeek_log(file_path):
    """
    Read a Zeek TSV log file and return a pandas DataFrame.
    """

    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"Could not read Zeek log: file not found: {file_path}")

    fields = None

    # Find the #fields line in the Zeek log
    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            if line.startswith("#fields"):
                fields = line.rstrip("\n").split("\t")[1:]
                break

    if fields is None:
        raise ValueError(f"Could not find #fields header in Zeek log: {file_path}")

    # Read the actual Zeek data
    df = pd.read_csv(
        file_path,
        sep="\t",
        comment="#",
        header=None,
        names=fields
    )

    return df


if __name__ == "__main__":
    log_file = "data/processed/zeek/conn.log"

    df = read_zeek_log(log_file)

    print("\n=== Zeek Connection Log ===")
    print(df)

    print("\n=== Column Names ===")
    print(df.columns.tolist())

    print("\n=== Number of Records ===")
    print(len(df))
