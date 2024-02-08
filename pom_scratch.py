import os
import xml.etree.ElementTree as ET

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


repo_path = "/home/pamusuo/research/permissions-manager/repos4analysis/jettison"
package_name = "org.codehaus.jettison:jettison"

package_dir = get_package_dir(repo_path, package_name)

if package_dir:
    print("Package directory:", package_dir)
else:
    print("Package not found in repository.")
