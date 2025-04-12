# CVE_Analyzer
GenAI CVE Analyzer for SLES15 SP3


Overall Purpose
You're building a pipeline that:

Accepts a list of CVEs (e.g., CVE-2021-47659)

Fetches affected packages and fixed versions for specific SUSE platforms

Formats, flattens, and summarizes that data

Outputs it in .csv format for analysis/reporting

🧩 agent1.py — 🔍 Fetch + Format CVE Data
🔧 Purpose:
This is the crawler/extractor module. It:

Takes a list of CVE IDs

Fetches SUSE’s CVE web page content

Extracts affected platforms, packages, and fixed versions

Outputs a grouped CSV (e.g., cve_packages_fix_versions.csv)

📦 Output:
csv
Copy
Edit
CVE_ID,Platform_1,Packages_Affected_1,Platform_2,Packages_Affected_2
CVE-2021-47659,"SUSE Linux Enterprise Server 15 SP3","[('rpm', '4.14.1-150300.46.1')]","SUSE Linux Enterprise Module for Basesystem 15 SP3","[('libsolv', '0.7.15-150300.3.3.1')]"
🧩 agent2.py — 🪓 Flatten + Categorize Data
🔧 Purpose:
This module flattens grouped data from agent1:

Breaks out nested platform/package details into rows

Prepares the data for easier filtering or analysis

📦 Output:
csv
Copy
Edit
CVE_ID,Platform,Package_Affected,Fixed_Version
CVE-2021-47659,SUSE Linux Enterprise Server 15 SP3,rpm,4.14.1-150300.46.1
CVE-2021-47659,SUSE Linux Enterprise Module for Basesystem 15 SP3,libsolv,0.7.15-150300.3.3.1
🧩 agent3.py — 📊 Create Summary CSV
🔧 Purpose:
This module generates a final summary from the flattened CSV:

Removes duplicates

Optionally reorders columns

Saves clean cve_summary.csv for final reports

📦 Output:
Identical structure to flattened CSV — clean and deduped.

🖥️ app.py — 🚀 Streamlit or CLI Entry Point
🔧 Purpose:
This is the main entry point of the pipeline. It:

Accepts CVE input from user (Streamlit file uploader or CLI args)

Calls agent1 to crawl/extract

Calls agent2 to flatten data

Calls agent3 to create the final summary

Displays/export final result

📦 Flow:
plaintext
Copy
Edit
CVE IDs → agent1 → grouped.csv
grouped.csv → agent2 → flattened.csv
flattened.csv → agent3 → cve_summary.csv
🔄 Typical File Flow:
plaintext
Copy
Edit
User Input (CVE IDs)
     |
     v
🧠 agent1.py  —> `cve_packages_fix_versions.csv`
     |
     v
🧠 agent2.py  —> `cve_flattened.csv`
     |
     v
🧠 agent3.py  —> `cve_summary.csv`
     |
     v
🖥️ app.py    —> Display/Export Final Output
🧪 Example Use Case
You input:

css
Copy
Edit
["CVE-2021-47659", "CVE-2020-0110"]
Output:

csv
Copy
Edit
CVE_ID,Platform,Package_Affected,Fixed_Version
CVE-2021-47659,SUSE Linux Enterprise Module for Basesystem 15 SP3,libsolv,0.7.15-150300.3.3.1
CVE-2021-47659,SUSE Linux Enterprise Server 15 SP3,rpm,4.14.1-150300.46.1
...
