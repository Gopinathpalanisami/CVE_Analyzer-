import pandas as pd

def create_cve_summary(input_csv, output_csv):
    try:
        df = pd.read_csv(input_csv)

        expected_columns = {'CVE_ID', 'Platform', 'Package_Affected', 'Fixed_Version'}
        if not expected_columns.issubset(df.columns):
            raise ValueError(f"❌ Expected columns: {', '.join(expected_columns)}")

        # Remove duplicates just in case
        df = df.drop_duplicates(subset=["Platform", "CVE_ID", "Package_Affected", "Fixed_Version"])

        # Save as flat summary (used by pipeline)
        df.to_csv(output_csv, index=False)
        print(f"✅ Summary written to {output_csv}")

    except Exception as e:
        print(f"❌ Error in create_cve_summary: {e}")
