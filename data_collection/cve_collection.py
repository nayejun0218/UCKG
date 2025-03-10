import requests
import os
import json
import time
import datetime
import sqlite3
import logging
import xml.etree.ElementTree as ET
from process import shared_functions as sf
from time import sleep

logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d, %(funcName)s)')
logger = logging.getLogger('collect_logger')

uco_ontology = os.environ['UCO_ONTO_PATH']
root_folder = os.environ['ROOT_FOLDER']
vol_path = os.environ['VOL_PATH']

def format_datetime_string(datetime_string):
    date_part, time_part = datetime_string.split(" ")
    seconds_part, milliseconds_part = time_part.split(".")
    milliseconds_part = milliseconds_part[:3]
    formatted_datetime = f"{date_part}T{seconds_part}.{milliseconds_part}"
    return formatted_datetime

def get_cwe_id_list():
    xml_file_path = './data/cwe/cwe_dict.xml'

    target_path = {
        'Weaknesses': './{http://cwe.mitre.org/cwe-7}Weaknesses',
        'Weakness': './{http://cwe.mitre.org/cwe-7}Weakness',
        'ID': './ID'
    }

    tree = ET.parse(xml_file_path)
    root = tree.getroot()
    extracted_ids = []

    for weaknesses in root.findall(target_path['Weaknesses']):
        for weakness in weaknesses.findall(target_path['Weakness']):
            id_value = weakness.get('ID')
            if id_value is not None:
                extracted_ids.append("CWE-" + str(id_value).strip())

    return extracted_ids

def cve_init():
    vol_path = os.environ['VOL_PATH']
    cve_db_file = os.path.join(vol_path, 'cve_database.db')
    with sqlite3.connect(cve_db_file) as conn:
        cursor = conn.cursor()

        logger.info("Starting CVE data extraction from NVD")
        start_index = 0

        cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='cve_meta'")
        if cursor.fetchone():
            cursor.execute(f"SELECT offset FROM cve_meta")
            row = cursor.fetchone()
            start_index = row[0]

    start_index = 0
    cve_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex=" 
    response = requests.get(f"{cve_api_url}{start_index}&resultsPerPage=2000")

    cves = {"cves": []}
    cwe_id_list = get_cwe_id_list()

    while response.status_code in [200, 403, 503]:
        if response.status_code in [403, 503]:
            for i in range(4):
                if i == 3:
                    logger.info("Unable to receive response, exiting...")
                    return
                
                logger.info(f"Retry #{i + 1}: Waiting for 10 seconds...")
                time.sleep(10)
                response = requests.get(f"{cve_api_url}{start_index}&resultsPerPage=2000")
                if response.status_code == 200:
                    break

        json_data = response.json()

    for cve in json_data["vulnerabilities"]:
        cwes = []
        cpes = []
        try:
            for weakness in cve['cve']['weaknesses']:
                for desc in weakness['description']:
                    weakness_value = desc['value'].strip()
                    if weakness_value in cwe_id_list:
                        cwes.append({"cwe": {"id": desc['value'], "cve_id": cve['cve']['id']}})

            for product in cve['cve']['configurations']:
                cpeMetaInfo = product['nodes'][0]['cpeMatch'][0]
                if (cpeMetaInfo['criteria']):
                    cpes.append({"cpe": {"cpeName": cpeMetaInfo['criteria'], "cve_id": cve['cve']['id']}})
        except Exception:
            pass

    cves["cves"].append({
        "cve": {
            "id": cve['cve']["id"],
            "lastModified": cve['cve']["lastModified"],
            "published": cve['cve']["published"],
            "descriptions": cve['cve']['descriptions'],
            "cwes": cwes,
            "cpes": cpes
        }
    })

    with open("./data/cve/cves.json", "w+") as json_file:
        json.dump(cves, json_file, indent=4)

    successfully_mapped = sf.call_mapper_update("cve")
    successfully_mapped2 = True

    if successfully_mapped and successfully_mapped2:
        if len(json_data["vulnerabilities"]) < 2000:
            sf.call_ontology_updater(reason=True)
        else:
            sf.call_ontology_updater()

