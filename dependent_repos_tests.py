import concurrent.futures
import requests
import json
import queue
import os
import subprocess
import sys
import threading
import xml.etree.ElementTree as ET

base_dir = "/home/pamusuo/research/permissions-manager"
repo_base_dir = os.path.join(base_dir, "repos4analysis")

def process_github_urls(shared_queue, input_file, output_file, base_url):
    with open(input_file, 'r') as file:
        lines = file.readlines()

    with open(output_file, 'w') as output:
        output.write("Fetching Dependent Repos\n")

    for line in lines:
        github_url, maven_package = line.strip().split()
        target_url = f"{base_url}{maven_package}"
        
        print(f"Processing package {maven_package}")
        with open(output_file, 'a') as output:
            output.write(f"{maven_package} - {github_url}")

        initial_response = invoke_url(target_url)
        
        if initial_response is None:
            with open(output_file, 'a') as output:
                output.write(f"\nError fetching total dependencies count for {maven_package}\n\n")
            continue

        total_dependencies_count = get_total_dependencies_count(initial_response)

        dependents_url = f"{target_url}/dependencies"

        # Determine the number of pages for pagination
        pages = (total_dependencies_count // 500) + 1

        dependent_objects = []

        for page in range(1, pages + 1):

            if (pages > 1):
                dependents_url = f"{dependents_url}?page={page}&per_page=500"

            response = invoke_url(dependents_url)

            if response is None:
                with open(output_file, 'a') as output:
                    output.write(f"\nError invoking URL {dependents_url}\n\n")
                break

            if response.status_code == 200:
                data = response.json()
                filtered_objects = filter_objects(data)

                dependent_objects.extend(filtered_objects)

                
            else:
                print(f"Error: Response code is {response.status_code}")
                with open(output_file, 'a') as output:
                    output.write(f"Error: Response code is {response.status_code}\n\n")

        dependent_objects = list({d['id']: d for d in dependent_objects}.values())

        if (len(dependent_objects) == 0):
            continue
        
        with open(output_file, 'a') as output:
            output.write(f" - {len(dependent_objects)}\n")

        if len(dependent_objects) > 10:
            dependent_objects.sort(key=lambda x: x['repository']['stargazers_count'], reverse=True)

        repo_urls = []

        for obj in dependent_objects:
            repository_name = obj['repository']['full_name']
            properties = {
                'archived': obj['repository']['archived'],
                'fork': obj['repository']['fork'],
                'html_url': obj['repository']['html_url'],
                'stargazers_count': obj['repository']['stargazers_count'],
                'forks_count': obj['repository']['forks_count'],
                'subscribers_count': obj['repository']['subscribers_count'],
            }
            with open(output_file, 'a') as output:
                output.write(f"{repository_name}: {properties}\n")

            repo_urls.append({'package_name': maven_package, 'repo_name': repository_name, 'github_url': properties['html_url']})

        shared_queue.put(repo_urls[:10])
        
        with open(output_file, 'a') as output:
            output.write("\n")
    

    # Signal the consumer to stop
    shared_queue.put(None)

def invoke_url(url, retry=True):
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as e:
        if retry:
            print(f"Retrying... ({str(e)})")
            return invoke_url(url, retry=False)
        else:
            return None

def filter_objects(data):
    return [obj for obj in data if obj['manifest']['filepath'] == 'pom.xml' and obj['repository']['language'] == 'Java']

def get_total_dependencies_count(response):

    if response == None:
        return
    try:
        data = response.json()
        return data.get('dependents_count', 0)
    except (json.JSONDecodeError, KeyError):
        return None


def run_mvn_tests(repo, output_file):

    package_name = repo['package_name']
    github_url = repo['github_url']

    print(f"Cloning and testing {github_url}")
    # Extract repository name from GitHub URL
    repo_name = github_url.split('/')[-1]

    # Clone the repository into the repos directory if it doesn't exist
    repo_dir = os.path.join(repo_base_dir, repo_name)

    if not os.path.exists(repo_dir):
        try:
            clone_repo(github_url, repo_dir)
        except subprocess.CalledProcessError as e:
            print(f"Error {e}")
            with open(output_file, 'a') as file:
                file.write(f"{package_name} - {repo_name} - Repo cloning failed\n")
            return None

    # Look for the path to the pom.xml file
    pom_path = os.path.join(repo_dir, 'pom.xml')
    if not pom_path or not os.path.exists(pom_path):
        print(f"Error: pom.xml file not found in {repo_name}")
        with open(output_file, 'a') as file:
            file.write(f"{package_name} - {repo_name} - Pom.xml not found\n")
        return None

    # Inject jacoco into the pom.xml file (assuming Jacoco plugin is used)
    inject_jacoco(pom_path)

    # Run 'mvn test' from root
    test_success = run_maven_test(repo_dir)
    
    if not test_success:
        with open(output_file, 'a') as file:
            file.write(f"{package_name} - {repo_name} - Maven test failed\n")
        return None

    # Get the jacoco xml file from the target directory
    jacoco_xml_path = get_jacoco_xml_path(repo_dir)

    if jacoco_xml_path is None or not os.path.exists(jacoco_xml_path):
        print(f"Jacoco file {jacoco_xml_path} not found")
        with open(output_file, 'a') as file:
            file.write(f"{package_name} - {repo_name} - Jacoco.xml not found\n")
        return None

    # Parse the jacoco xml file to get the test coverage
    coverage_percentage = get_line_coverage_percentage(jacoco_xml_path)

    # Write to output file "<repo-name> - <coverage>%"
    with open(output_file, 'a') as file:
        file.write(f"{package_name} - {repo_name} - {coverage_percentage}%\n")


def get_jacoco_xml_path(repo_dir):
    
    for root, dirs, files in os.walk(repo_dir):
        for file in files:
            if file.endswith('jacoco.xml'):
                jacoco_path = os.path.join(root, file)
                return jacoco_path

    return None

def clone_repo(url, repo_dir):
    subprocess.run(["git", "clone", url, repo_dir], check=True)


def find_pom_file(directory):
    for root, dirs, files in os.walk(directory):
        if 'pom.xml' in files:
            return os.path.join(root, 'pom.xml')
    return None

def inject_jacoco(pom_file_path):
    add_jacoco_configuration(pom_file_path)
    print(f"JaCoCo configuration added to {pom_file_path}")

    remove_ns0_from_file(pom_file_path)
    print(f"Removed 'ns0' occurrences from {pom_file_path}")


def remove_ns0_from_file(file_path):
    try:
        # Read the content of the file
        with open(file_path, 'r') as file:
            content = file.read()

        # Remove all occurrences of 'ns0:'
        modified_content = content.replace('ns0:', '')

        # Write the modified content back to the file
        with open(file_path, 'w') as file:
            file.write(modified_content)

        print(f'Successfully removed "ns0:" from {file_path}')

    except FileNotFoundError:
        print(f'Error: File not found - {file_path}')

    except Exception as e:
        print(f'An error occurred: {str(e)}')


        
def add_jacoco_configuration(pom_file):
    # Load the XML file with namespace information
    tree = ET.parse(pom_file)
    root = tree.getroot()

    # Extract namespace information
    namespace = root.tag.split('}')[0] + '}'

    # Find or create the build section
    build = root.find(".//{}build".format(namespace))
    if build is None:
        build = ET.Element("{}build".format(namespace))
        root.append(build)

    # Find or create the plugins section within the build section
    plugins = build.find(".//{}plugins".format(namespace))
    if plugins is None:
        plugins = ET.SubElement(build, "{}plugins".format(namespace))

    # Check if JaCoCo plugin already exists
    existing_jacoco = plugins.find(".//{}artifactId[.='jacoco-maven-plugin']".format(namespace))
    if existing_jacoco is not None:
        print("JaCoCo plugin configuration already exists in the pom.xml.")
        return

    # Define JaCoCo plugin configuration
    jacoco_plugin = ET.Element("{}plugin".format(namespace))
    jacoco_plugin_groupId = ET.SubElement(jacoco_plugin, "{}groupId".format(namespace))
    jacoco_plugin_groupId.text = "org.jacoco"
    jacoco_plugin_artifactId = ET.SubElement(jacoco_plugin, "{}artifactId".format(namespace))
    jacoco_plugin_artifactId.text = "jacoco-maven-plugin"
    jacoco_plugin_version = ET.SubElement(jacoco_plugin, "{}version".format(namespace))
    jacoco_plugin_version.text = "0.8.7"  # Use the latest version

    # Add executions element
    executions = ET.SubElement(jacoco_plugin, "{}executions".format(namespace))

    # Add prepare-agent goal
    prepare_agent_execution = ET.SubElement(executions, "{}execution".format(namespace))
    prepare_agent_goals = ET.SubElement(prepare_agent_execution, "{}goals".format(namespace))
    prepare_agent_goal = ET.SubElement(prepare_agent_goals, "{}goal".format(namespace))
    prepare_agent_goal.text = "prepare-agent"

    # Add report goal
    report_execution = ET.SubElement(executions, "{}execution".format(namespace))
    report_execution_id = ET.SubElement(report_execution, "{}id".format(namespace))
    report_execution_id.text = "report"
    report_execution_phase = ET.SubElement(report_execution, "{}phase".format(namespace))
    report_execution_phase.text = "test"
    report_goals = ET.SubElement(report_execution, "{}goals".format(namespace))
    report_goal = ET.SubElement(report_goals, "{}goal".format(namespace))
    report_goal.text = "report"

    # Add JaCoCo plugin configuration to the plugins section
    plugins.append(jacoco_plugin)

    # Save the modified XML back to the file
    tree.write(pom_file, encoding="utf-8", xml_declaration=True)

def run_maven_test(directory):
    maven_test_command = ['mvn', 'test', '-Dmaven.test.failure.ignore=true']

    try:
        process = subprocess.Popen(maven_test_command, cwd=directory)
        
        # Wait for the process to complete or timeout
        process.wait(timeout=3600)
        print(f"Process {maven_test_command} returned")
        return True
    except subprocess.TimeoutExpired:
        print("Timeout exceeded. Terminating mvn test.")
        process.terminate()
        process.wait()
        return False
    except subprocess.CalledProcessError as e:
        print(f"Error {e}")
        
        return False
    except Exception as e:
        print(f"An error occurred: {e}")
        return False

def parse_jacoco_xml(xml_path):
    # Assume some logic for parsing the Jacoco XML file and extracting coverage percentage
    tree = ET.parse(xml_path)
    root = tree.getroot()
    # Extract coverage percentage from root or specific element
    coverage_percentage = root.find('.//counter[@type="INSTRUCTION"]').attrib['covered']
    return coverage_percentage

def get_line_coverage_percentage(jacoco_xml_file):
    tree = ET.parse(jacoco_xml_file)
    root = tree.getroot()

    # Find the counter elements for lines
    counters = root.findall(".//counter[@type='LINE']")

    # Extract covered and missed line counts
    covered_lines = 0
    missed_lines = 0
    for count in counters:
        covered_lines = covered_lines + int(count.get("covered"))
        missed_lines = missed_lines + int(count.get("missed"))
    print(f"Number of covered_lines {covered_lines}")
    print(f"Number of missed_lines {missed_lines}")
    # Calculate line coverage percentage
    total_lines = covered_lines + missed_lines
    line_coverage_percentage = (covered_lines / total_lines) * 100 if total_lines > 0 else 100

    return line_coverage_percentage


def handle_mvn_tests(shared_queue, output_file):

    with open(output_file, 'w') as output:
        output.write("Processing Maven Test Coverage\n")
    
    while True:
        repo_list = shared_queue.get()
        if repo_list is None:
            break
        
        print(f"Received repos: {len(repo_list)}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:

            for repo in repo_list:
                # Submit a task for the current repo to the thread pool
                future = executor.submit(run_mvn_tests, repo, output_file)

                # Wait for the task to complete
                try:
                    future.result(timeout=900)  # Timeout set to 5 minutes (300 seconds)
                except concurrent.futures.TimeoutError:
                    print(f"Timeout exceeded for repo: {repo}")
                    with open(output_file, 'a') as file:
                        file.write(f"{repo['package_name']} - {repo['repo_name']} - Timeout\n")
                except Exception as e:
                    print(f"Error in repo: {repo}, {e}")
                    with open(output_file, 'a') as file:
                        file.write(f"{repo['package_name']} - {repo['repo_name']} - Error\n\n")
                        file.write(f"{e}\n\n")
    


# Example usage:
input_file_path = 'github_urls.txt'  # Replace with the actual path of your input file
dependent_repos_file = 'dependent_repos_file.txt'  # Replace with the desired output file path
repo_coverage_file = 'repo_coverage.txt'
base_github_url = 'https://repos.ecosyste.ms/api/v1/usage/maven/'  # Replace with your base GitHub URL

# Create a shared queue
shared_queue = queue.Queue()

producer_thread = threading.Thread(target=process_github_urls, args=(shared_queue, input_file_path, dependent_repos_file, base_github_url))
consumer1_thread = threading.Thread(target=handle_mvn_tests, args=(shared_queue, repo_coverage_file))

producer_thread.start()
consumer1_thread.start()

consumer1_thread.join()
producer_thread.join()
