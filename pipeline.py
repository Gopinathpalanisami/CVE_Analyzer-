import pandas as pd

def load_grouped_cve_data(summary_csv="cve_summary.csv"):
    df = pd.read_csv(summary_csv)

    # Debug: Print actual columns found in the CSV
    print("📄 Columns in CSV:", list(df.columns))

    # Strip column names just in case of leading/trailing spaces
    df.columns = df.columns.str.strip()

    required_columns = {"Platform", "CVE_ID", "Package_Affected", "Fixed_Version"}
    if not required_columns.issubset(df.columns):
        missing = required_columns - set(df.columns)
        raise ValueError(
            f"Missing columns in {summary_csv}: {missing}. Required: {required_columns}"
        )

    grouped = df.groupby(["Platform", "CVE_ID"])

    for (platform, cve), group in grouped:
        print(f"\n\033[1mPlatform {platform}\033[0m\n")
        print(f"{cve:<23}", end="")

        for i, row in enumerate(group.itertuples(), 1):
            pkg = row.Package_Affected
            ver = row.Fixed_Version
            if i == 1:
                print(f"{pkg:<25} , {ver}")
            else:
                print(f"{'':<23}{pkg:<25} , {ver}")

    #return grouped
    grouped_dict = {
        (platform, cve): list(zip(group["Package_Affected"], group["Fixed_Version"]))
        for (platform, cve), group in grouped
    }
    return grouped_dict
