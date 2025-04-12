import asyncio
import pandas as pd
import re
import nest_asyncio
from bs4 import BeautifulSoup
from crawl4ai import AsyncWebCrawler, CacheMode, CrawlerRunConfig

nest_asyncio.apply()

async def fetch_cve_data(cve):
    base_url = "https://www.suse.com/security/cve/"
    url = f"{base_url}{cve}.html"
    result_data = []

    try:
        print(f"🌐 Fetching: {url}")
        crawler_run_config = CrawlerRunConfig(cache_mode=CacheMode.BYPASS)
        async with AsyncWebCrawler() as crawler:
            result = await crawler.arun(url=url, config=crawler_run_config)

            if not hasattr(result, "html") or not result.html:
                print(f"❌ No HTML content found for {cve}")
                return result_data

            soup = BeautifulSoup(result.html, "html.parser")
            platforms = soup.find_all("tr")

            server_15_sp3_ltss = []
            module_basesystem_15_sp3 = []

            for row in platforms:
                columns = row.find_all("td")
                if len(columns) > 1:
                    platform_name = columns[0].text.strip()

                    if "SUSE Linux Enterprise Server 15 SP3-LTSS" in platform_name:
                        packages = columns[1].find_all("code", class_="cve-released")
                        for package in packages:
                            package_info = package.text.strip()
                            match = re.match(r"^(\S+)\s*>=\s*([\d\.\-\w]+)", package_info)
                            if match:
                                server_15_sp3_ltss.append((match.group(1), match.group(2)))

                    elif "SUSE Linux Enterprise Module for Basesystem 15 SP3" in platform_name:
                        packages = columns[1].find_all("code", class_="cve-released")
                        for package in packages:
                            package_info = package.text.strip()
                            match = re.match(r"^(\S+)\s*>=\s*([\d\.\-\w]+)", package_info)
                            if match:
                                module_basesystem_15_sp3.append((match.group(1), match.group(2)))

            if server_15_sp3_ltss or module_basesystem_15_sp3:
                result = {"CVE_ID": cve}
                if server_15_sp3_ltss:
                    result["Platform_1"] = "SUSE Linux Enterprise Server 15 SP3-LTSS"
                    result["Packages_Affected_1"] = server_15_sp3_ltss
                if module_basesystem_15_sp3:
                    result["Platform_2"] = "SUSE Linux Enterprise Module for Basesystem 15 SP3"
                    result["Packages_Affected_2"] = module_basesystem_15_sp3
                result_data.append(result)

    except Exception as e:
        print(f"❌ Error fetching data for {cve}: {e}")

    return result_data

def export_grouped_report(all_results):
    output_lines = ["CVE_ID\t\t\tPlatform_1\t\t\tPackages_Affected_1\t\t\tPlatform_2\t\t\tPackages_Affected_2"]
    for entry in all_results:
        line = f"{entry['CVE_ID']}\t{entry.get('Platform_1', '')}\t{entry.get('Packages_Affected_1', '')}\t{entry.get('Platform_2', '')}\t{entry.get('Packages_Affected_2', '')}"
        output_lines.append(line)

    with open("cve_packages_grouped.txt", "w") as f:
        f.write("\n".join(output_lines))
    print("✅ Grouped report saved as 'cve_packages_grouped.txt'")

async def extract_packages_fix_versions(cve_ids):
    all_results = []
    flattened_rows = []

    for cve in cve_ids:
        data = await fetch_cve_data(cve)
        all_results.extend(data)

        for entry in data:
            cve_id = entry["CVE_ID"]
            if "Platform_1" in entry:
                platform = entry["Platform_1"]
                for pkg, ver in entry["Packages_Affected_1"]:
                    flattened_rows.append({
                        "CVE_ID": cve_id,
                        "Platform": platform,
                        "Package_Affected": pkg,
                        "Fixed_Version": ver
                    })
            if "Platform_2" in entry:
                platform = entry["Platform_2"]
                for pkg, ver in entry["Packages_Affected_2"]:
                    flattened_rows.append({
                        "CVE_ID": cve_id,
                        "Platform": platform,
                        "Package_Affected": pkg,
                        "Fixed_Version": ver
                    })

    if all_results:
        # Save wide format (grouped) CSV
        df = pd.DataFrame(all_results, columns=["CVE_ID", "Platform_1", "Packages_Affected_1", "Platform_2", "Packages_Affected_2"])
        df.to_csv("cve_packages_fix_versions.csv", index=False)
        print("✅ Wide CSV saved as 'cve_packages_fix_versions.csv'")

        # Save flat format CSV for agent2.py
        df_flat = pd.DataFrame(flattened_rows)
        df_flat.to_csv("cve_packages_flat.csv", index=False)
        print("✅ Flat CSV saved as 'cve_packages_flat.csv'")

        export_grouped_report(all_results)
    else:
        print("❌ No data found. Please verify the CVE IDs or SUSE page structure.")

def crawl_and_format_cves(cve_ids):
        asyncio.run(extract_packages_fix_versions(cve_ids))

if __name__ == "__main__":
    cve_list_file = "cve_list.csv"
    cve_data = pd.read_csv(cve_list_file)

    if "CVE_ID" in cve_data.columns:
        cve_ids = cve_data["CVE_ID"].tolist()
        asyncio.run(extract_packages_fix_versions(cve_ids))
    else:
        print("❌ The CSV file must have a 'CVE_ID' column.")
