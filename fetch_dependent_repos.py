import requests
import json

def process_github_urls(input_file, output_file, base_url):
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

        with open(output_file, 'a') as output:
            output.write("\n")

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

# Example usage:
input_file_path = 'vuln_packages.txt'  # Replace with the actual path of your input file
output_file_path = 'vuln_dependent_repos.txt'  # Replace with the desired output file path
base_github_url = 'https://repos.ecosyste.ms/api/v1/usage/maven/'  # Replace with your base GitHub URL

process_github_urls(input_file_path, output_file_path, base_github_url)
