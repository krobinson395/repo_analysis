import os
import xml.etree.ElementTree as ET

def get_jacoco_xml_paths(repo_dir):
    
    for root, dirs, files in os.walk(repo_dir):
        for file in files:
            if file.endswith('jacoco.xml'):
                jacoco_path = os.path.join(root, file)
                return jacoco_path

    return None

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

jacoco_path = get_jacoco_xml_paths("/home/pamusuo/research/permissions-manager/repos4analysis/pikaq")

print(f"Jacoco path: {jacoco_path}")

coverage = get_line_coverage_percentage(jacoco_path)

print(f"Coverage: {coverage}")
