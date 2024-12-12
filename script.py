import json
import os
import zipfile
import requests
from pathlib import Path
from lxml import etree

def fetch_and_parse_cwe_data():
    # Download the latest CWE data
    print("Downloading CWE data...")
    url = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
    response = requests.get(url, timeout=10)
    with open('cwec_latest.xml.zip', 'wb') as f:
        f.write(response.content)

    # Extract the XML file from the ZIP
    with zipfile.ZipFile('cwec_latest.xml.zip', 'r') as zip_ref:
        zip_ref.extractall(".")

    # Locate the extracted XML file
    cwe_file_path = next(f for f in os.listdir() if f.endswith(".xml"))

    # Parse the extracted XML file
    cwes = []
    with open(cwe_file_path, 'rb') as file:
        cwe_xml = etree.parse(file, etree.XMLParser(resolve_entities=False))

    # Retrieve namespaces from the XML root
    namespaces = cwe_xml.getroot().nsmap

    # Find all Weakness elements
    weaknesses_xml = cwe_xml.findall('./Weaknesses/Weakness', namespaces=namespaces)

    for w in weaknesses_xml:
        if w.attrib['Status'] == 'Deprecated':
            continue

        # Append the CWE data to the list
        cwes.append({
            'name': f"CWE-{w.attrib['ID']}: {w.attrib['Name']}",
            'description': w.find('./Description', namespaces=namespaces).text,
        })

    # Sort the CWE list by 'name'
    cwes = sorted(cwes, key=lambda cwe: cwe['name'])

    # Save the data to a JSON file
    out_path = Path(__file__).parent / 'cwe.json'
    with open(out_path, 'w') as f:
        json.dump(cwes, f, indent=2)

    # Remove downloaded and extracted files for cleanup
    os.remove('cwec_latest.xml.zip')
    os.remove(cwe_file_path)

    print("CWE data successfully updated and saved to cwe.json")

if __name__ == '__main__':
    fetch_and_parse_cwe_data()
