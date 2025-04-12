import streamlit as st
import pandas as pd
import os
from agent1 import crawl_and_format_cves
from agent2 import categorize_by_cve
from agent3 import create_cve_summary

st.set_page_config(page_title="GenAI CVE Analyzer for SLES15 SP3", layout="wide")

st.title("🧠 GenAI CVE Analyzer for SLES15 SP3")
st.markdown("Upload a file with CVE IDs or type them manually below.")

uploaded_file = st.file_uploader("Upload CVE list (.csv with 'CVE_ID' column)", type="csv")

manual_input = st.text_area("Or enter CVE IDs (comma or newline separated):", height=100)

if st.button("🔍 Analyze CVEs"):
    cve_list = []

    if uploaded_file:
        df = pd.read_csv(uploaded_file)
        cve_list = df['CVE_ID'].dropna().unique().tolist()

    if manual_input:
        manual_cves = [cve.strip() for cve in manual_input.replace(",", "\n").split("\n") if cve.strip()]
        cve_list.extend(manual_cves)

    cve_list = list(set(cve_list))  # Deduplicate

    if not cve_list:
        st.warning("⚠️ Please upload a file or enter CVE IDs.")
    else:
        st.info("⏳ Crawling and formatting CVE data. Please wait...")
        crawl_and_format_cves(cve_list)
        #flatten_cve_data()
        categorize_by_cve("cve_packages_fix_versions.csv", "cve_flattened.csv")
        #summarize_cves()
        create_cve_summary("cve_flattened.csv", "cve_summary.csv")
        st.success("✅ Crawl & formatting complete!")

        df_summary = pd.read_csv("cve_summary.csv")
        st.subheader("📦 Affected Packages with Fixes (Grouped View)")

        cve_data = {}

        for _, row in df_summary.iterrows():
            platform = row["Platform"]
            cve_id = row["CVE_ID"]
            package = row["Package_Affected"]
            fixed_ver = row["Fixed_Version"]
            key = (platform, cve_id)
            if key not in cve_data:
                cve_data[key] = []
            cve_data[key].append((package, fixed_ver))

        for (platform, cve), pkgs in cve_data.items():
            with st.expander(f"{platform} → {cve}"):
                grouped_output = [
                    f"Platform: {platform}",
                    f"{cve}:"
                ] + [f"  - {pkg}, {ver}" for pkg, ver in pkgs]

                st.markdown("```yaml\n" + "\n".join(grouped_output) + "\n```")
