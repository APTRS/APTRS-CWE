import json
import os
import zipfile
import requests
from pathlib import Path
from lxml import etree

def fetch_and_parse_cwe_data():
    # Download the latest CWE data
    print("Downloading CWE data...")
    cwe_zip_url = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
    zip_file_name = 'cwec_latest.xml.zip'
    response = requests.get(cwe_zip_url, timeout=10)
    with open(zip_file_name, 'wb') as zip_file:
        zip_file.write(response.content)

    # Extract the XML file from the ZIP
    with zipfile.ZipFile(zip_file_name, 'r') as zip_ref:
        zip_ref.extractall(".")

    # Locate the extracted XML file
    extracted_xml_file = next(file_name for file_name in os.listdir() if file_name.endswith(".xml"))

    # Parse the extracted XML file
    cwe_entries = []
    with open(extracted_xml_file, 'rb') as xml_file:
        xml_tree = etree.parse(xml_file, etree.XMLParser(resolve_entities=False))

    # Retrieve namespaces from the XML root
    xml_namespaces = xml_tree.getroot().nsmap

    # Find all Weakness elements
    weakness_elements = xml_tree.findall('./Weaknesses/Weakness', namespaces=xml_namespaces)

    for weakness in weakness_elements:
        if weakness.attrib['Status'] == 'Deprecated':
            continue

        # Append the CWE data to the list
        cwe_entries.append({
            'name': f"CWE-{weakness.attrib['ID']}: {weakness.attrib['Name']}",
            'description': weakness.find('./Description', namespaces=xml_namespaces).text,
        })

    # Sort the CWE list by 'name'
    cwe_entries = sorted(cwe_entries, key=lambda cwe: cwe['name'])

    # Save the data to a JSON file
    output_json_path = Path(__file__).parent / 'cwe.json'
    with open(output_json_path, 'w') as json_file:
        json.dump(cwe_entries, json_file, indent=2)

    # Remove downloaded and extracted files for cleanup
    os.remove(zip_file_name)
    os.remove(extracted_xml_file)

    print("CWE data successfully updated and saved to cwe.json")

if __name__ == '__main__':
    fetch_and_parse_cwe_data()
