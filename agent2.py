import pandas as pd
import ast

def categorize_by_cve(input_csv, output_csv):
    try:
        df = pd.read_csv(input_csv)

        required_cols = ["CVE_ID", "Platform_1", "Packages_Affected_1"]
        if not all(col in df.columns for col in required_cols):
            raise ValueError(f"Missing required columns in the input file.")

        flattened_rows = []

        for _, row in df.iterrows():
            cve_id = row["CVE_ID"]

            for i in [1, 2]:
                platform_col = f"Platform_{i}"
                packages_col = f"Packages_Affected_{i}"

                if pd.notna(row.get(platform_col)) and pd.notna(row.get(packages_col)):
                    try:
                        platform = row[platform_col]
                        packages = ast.literal_eval(row[packages_col])
                        for package, version in packages:
                            flattened_rows.append({
                                "CVE_ID": cve_id,
                                "Platform": platform,
                                "Package_Affected": package,
                                "Fixed_Version": version
                            })
                    except Exception as e:
                        print(f"⚠️ Error parsing {packages_col} for {cve_id}: {e}")

        flat_df = pd.DataFrame(flattened_rows)

        # Remove duplicates
        flat_df = flat_df.drop_duplicates(subset=["CVE_ID", "Platform", "Package_Affected", "Fixed_Version"])

        # Save to new CSV
        flat_df.to_csv(output_csv, index=False)
        print(f"✅ Categorized data saved to {output_csv}")

    except Exception as e:
        print(f"❌ Error during categorization: {e}")

if __name__ == "__main__":
    categorize_by_cve("cve_packages_fix_versions.csv", "cve_flattened.csv")
