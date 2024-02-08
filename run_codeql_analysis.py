import os
import subprocess
import json
import shutil
import xml.etree.ElementTree as ET

codeql = "/home/pamusuo/research/codeql/codeql/codeql"
base_dir = "/home/pamusuo/research/permissions-manager"
repo_base_dir = os.path.join(base_dir, "repos4analysis")
results_base_dir = os.path.join(base_dir, "repo_analysis/sarif_results")
delete_repos = False

def clone_repo(url, repo_dir):
    subprocess.run(["git", "clone", url, repo_dir], check=True)

def build_codeql_database(repo_dir, codeql_db_name):
    os.chdir(repo_dir)
    try:
        subprocess.run([codeql, "database", "create", codeql_db_name, "--language=java", "--overwrite"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error building CodeQL database: {e}")
        return False
    return True

def run_codeql_query(codeql_db_name, query_paths, codeql_output):
    try:
        subprocess.run([codeql, "database", "analyze", codeql_db_name, *query_paths, "--format=sarif-latest", f"--output={codeql_output}", "--rerun"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running CodeQL query: {e}")
        return False
    return True

def parse_sarif_file(sarif_path):
    # Replace with actual SARIF parsing logic

    try:
        with open(sarif_path, "r") as file:

            json_data = file.read()

        sarif_data = json.loads(json_data)

        findings_count = {"file-read": 0, "file-write": 0, "socket-connect": 0, "socket-server": 0, "runtime-exec": 0}

        runs = sarif_data.get('runs', [])
        for run in runs:
            results = run.get('results', [])
            for result in results:
                rule_id = result.get('ruleId', 'N/A')

                # Check if the result is from a test directory
                locations = result.get('locations', [])
                in_test_directory = any(
                    "src/test/java" in loc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
                    for loc in locations
                )

                if not in_test_directory:
                    if rule_id == "file-read-analysis":
                        findings_count["file-read"] += 1
                    elif rule_id == "file-write-analysis":
                        findings_count["file-write"] += 1
                    elif rule_id == "socket-connect-analysis":
                        findings_count["socket-connect"] += 1
                    elif rule_id == "socket-server-analysis":
                        findings_count["socket-server"] += 1
                    elif rule_id == "runtime-exec-analysis":
                        findings_count["runtime-exec"] += 1

        return findings_count

    except FileNotFoundError or json.JSONDecodeError as e:
        print(f"Error parsing Sarif file {e}")
        return None

def delete_repo(repo_dir):
    shutil.rmtree(repo_dir)

def get_package_name_from_pom(xml_file_path):
    try:
        # Parse the XML file
        tree = ET.parse(xml_file_path)
        root = tree.getroot()

        # get the namesapce from the root key
        namesp = root.tag.replace("project","")  

        # Get artifactId from root  
        artifactId_element = root.find(f"{namesp}artifactId")
        if artifactId_element is None:
            return None

        artifactId = artifactId_element.text

        # Get groupId from root or parent tag
        groupId_element = root.find(f"{namesp}groupId")
        if groupId_element is None:
            parent = root.find(f"{namesp}parent")
            groupId_element = parent.find(f"{namesp}groupId")
        if groupId_element is None:
            groupId_element = root.find(f".//{namesp}groupId")
        if groupId_element is None:
            return None

        groupId = groupId_element.text
        
        return f"{groupId}:{artifactId}"
    except ET.ParseError as e:
        print(f"Error parsing XML: {e}")
        return None


def get_package_dir(repo_path, package_name):
    """Returns the path to the subdirectory containing a pom.xml file that matches the provided package name within a repository.

    Args:
        repo_path: The path to the repository root directory.
        package_name: The maven package name (groupId:artifactId).

    Returns:
        The path to the subdirectory containing the matching pom.xml file, or None if not found.
    """

    for root, _, files in os.walk(repo_path):
        for file in files:
            if file.lower() == "pom.xml":
                pom_path = os.path.join(root, file)
                current_package_name = get_package_name_from_pom(pom_path)
                if current_package_name == package_name:
                    return os.path.dirname(pom_path)

    return None


def process_url(url_components, query_path, output_file):
    url = url_components[0]
    package_name = url_components[1]
    repo_name = url.split("/")[-1].replace(".git", "")
    repo_dir = os.path.join(repo_base_dir, repo_name)
    codeql_db_name = os.path.join(repo_dir, "codeql_db")
    codeql_output = os.path.join(results_base_dir, f"{repo_name}-results.sarif")

    print(f"Processing {repo_name}")

    if not os.path.exists(repo_dir):
        try:
            clone_repo(url, repo_dir)
        except subprocess.CalledProcessError:
            with open(output_file, "a") as f:
                f.write(f"{repo_name}, Cloning failed\n")
            return

    package_dir = get_package_dir(repo_dir, package_name)

    if package_dir is None:
        with open(output_file, "a") as f:
            f.write(f"{repo_name}, Pom.xml not found. Continuing...\n")
            package_dir = repo_dir

    if not build_codeql_database(package_dir, codeql_db_name):
        with open(output_file, "a") as f:
            f.write(f"{repo_name}, CodeQL build failed\n")
        return

    if not run_codeql_query(codeql_db_name, query_path, codeql_output):
        with open(output_file, "a") as f:
            f.write(f"{repo_name}, CodeQL query failed\n")
        return

    sarif_output = parse_sarif_file(codeql_output)

    with open(output_file, "a") as f:
        f.write(f"{repo_name}, {sarif_output}\n")

    if delete_repos:
        delete_repo(repo_dir)

if __name__ == "__main__":
    url_file = "github_urls.txt"
    query_paths = ["/home/pamusuo/research/codeql/vscode-codeql-starter/codeql-custom-queries-java/file-write.ql",
                    "/home/pamusuo/research/codeql/vscode-codeql-starter/codeql-custom-queries-java/file-read.ql",
                    "/home/pamusuo/research/codeql/vscode-codeql-starter/codeql-custom-queries-java/runtime-exec.ql",
                    "/home/pamusuo/research/codeql/vscode-codeql-starter/codeql-custom-queries-java/socket-connect.ql",
                    "/home/pamusuo/research/codeql/vscode-codeql-starter/codeql-custom-queries-java/socket-server.ql"]
    output_file = "/home/pamusuo/research/permissions-manager/repo_analysis/analysis_results.txt"

    with open(url_file, "r") as f:
        urls = f.readlines()

    with open(output_file, "w") as f:
        f.write("Analyzing package capabilities\n\n")

    for url_object in urls:
        url_components = url_object.split()
        process_url(url_components, query_paths, output_file)
