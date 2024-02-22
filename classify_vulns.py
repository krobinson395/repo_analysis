import pandas as pd
import math

# Load the xlsx file into a DataFrame
xlsx_file_path = '/home/pamusuo/research/permissions-manager/repo_analysis/Maven Vulnerabilities.xlsx'  # Replace with the actual path to your xlsx file
sheet_name = 'Randomized Study'  # Replace with the actual sheet name if different
df = pd.read_excel(xlsx_file_path, sheet_name=sheet_name)

# Define the vulnerability dictionary
vulnerabilities_dict = {
    "Deserialization": ["CWE-502"],
    "XXE": ["CWE-611"],
    "Path Traversal": ["CWE-22", "CWE-23", "CWE-73"],
    "Command Injection": ["CWE-78", "CWE-77", "CWE-74", "CWE-88"],
    "Code Injection": ["CWE-917", "CWE-94", "CWE-470"],
    "Web": ["CWE-352", "CWE-79", "CWE-444"],
    "SQL Injection": ["CWE-89"],
    "Resource Exhaustion": ["CWE-400", "CWE-770", "CWE-835", "CWE-776"],
    "Incorrect Behavior": ["CWE-193", "CWE-408", "CWE-440", "CWE-404", "CWE-755", "CWE-754"],
    "Memory Corruption": ["CWE-787", "CWE-120"],
    "Authentication/Authorization": ["CWE-863", "CWE-269", "CWE-279", "CWE-522", "CWE-287", "CWE-347", "CWE-384", "CWE-862", "CWE-295", "CWE-285"],
    "SSRF": ["CWE-918"],
    "3P Data Exposure": ["CWE-200", "CWE-379", "CWE-668", "CWE-377", "CWE-732", "CWE-552", "CWE-256", "CWE-319"],
    "Multiple": ["multiple"],
    "Nan": ["nan"],
    "Unclassified Input Validation": ["CWE-20"],
    "Other": ["CWE-668"]
}

# Create a dictionary to store CVEs under their respective vulnerabilities
output_dict = {vuln: [] for vuln in vulnerabilities_dict}

# Iterate through each row in the DataFrame
for index, row in df.iterrows():
    try:

        matching_vulns = set()
        
        cwe_id_string = row['CWE-ID']
        
        if cwe_id_string is not None and isinstance(cwe_id_string, str):
            cwe_ids = cwe_id_string.split(',')
        
            # Check for matching vulnerabilities for each CWE-ID
            for cwe_id in cwe_ids:
                for vuln, vuln_cwe_ids in vulnerabilities_dict.items():
                    if cwe_id in vuln_cwe_ids:
                        matching_vulns.add(vuln)

        else:
            cwe_id_string = "None"
            matching_vulns.add("Nan")
        
        # Determine the final vulnerability category
        if len(matching_vulns) == 1:
            vulnerability_category = matching_vulns.pop()
        elif len(matching_vulns) > 1:
            vulnerability_category = "Multiple"
        else:
            vulnerability_category = "Other"  # No matching vulnerabilities found
        
        # Add the CVE to the appropriate vulnerability category
        output_dict[vulnerability_category].append({
                'cve_id': row['CVE ID'],
                'package_affected': row['Package Affected'],
                'cwe_ids': cwe_id_string, 
                'summary': row['Summary']
            })

    except Exception as e:
        print(f"Error processing row {row}: \n{e}")
        exit(1)

# Print the output to a file
output_file_path = 'output_classifications.txt'  # Replace with the desired output file path
with open(output_file_path, 'w') as output_file:
    # Write output_dict to the file
    for vuln, cves in output_dict.items():
        output_file.write(f"{vuln} - {len(cves)}:\n")
        for cve in cves:
            output_file.write(f"  {cve['cve_id']} - {cve['package_affected']} - {cve['cwe_ids']} - {cve['summary']}\n")
        output_file.write("\n")
print(f"Output written to {output_file_path}")
