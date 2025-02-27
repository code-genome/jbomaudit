import glob
import os
import json
import collections
from tqdm import tqdm
import pickle
import matplotlib.pyplot as plt
from utils_tool.helper import *


def load_json(file_path):
    """
    Load a JSON file from the specified path.
    """
    with open(file_path, 'r') as f:
        return json.load(f)


class Stats:
    """
    A class to track various statistics during the dictionary enlargement process.
    """
    def __init__(self):
        self.total = 0    
        self.read_error = 0
        self.no_logs_count = 0
        self.read_purl_logs_error_count = 0
        self.package_list_is_empty_count = 0
        self.add_dic_from_new = 0


def enlarge_dic(jar_to_pkgs_dic): 
    """
    Enlarge the given dictionary with additional package data if available.
    """
    stat = Stats()
    enlarged_mapping = add_dic(jar_to_pkgs_dic, stat, './results/jarpkgtags/')

    # Ensure the metadata directory exists
    metadata_dir = "./metaDB/metadata/"
    if not os.path.exists(metadata_dir):
        os.makedirs(metadata_dir)  # Create missing directories

    # Write the JSON file
    with open(os.path.join(metadata_dir, "jar_to_pkgs_dic.json"), 'w') as f:
        json.dump(enlarged_mapping, f)


def add_dic(mapping, stat, directory):
    """
    Add new entries to the existing mapping dictionary from JSON files in the specified directory.
    """
    file_list = glob.glob(os.path.join(directory, '**/meta_info.json'), recursive=True)
    for file in tqdm(file_list, desc="Processing files"):
        gid = file.split("/")[-4]
        aid = file.split("/")[-3]
        vid = file.split("/")[-2]
        purl = f'{gid}|{aid}|{vid}'
        
        if purl in mapping:
            #print(f"Artifact {purl} is already added.")
            continue

        # Attempt to load package data
        try:
            pkg_json = load_json(file)
        except json.JSONDecodeError:
            stat.read_error += 1
            continue

        # Extract package list
        pkg_list = pkg_json.get("packages", {}).keys() if "packages" in pkg_json else []
        
        if not pkg_list:
            stat.package_list_is_empty_count += 1

        # Add new package list to mapping
        if purl not in mapping:
            mapping[purl] = list(pkg_list)
            stat.add_dic_from_new += 1

    #print(f"Added {stat.add_dic_from_new} new metadata entries.")
    return mapping


def switch_key_value(jar_to_pkgs_dic):
    """
    Switch key-value pairs from jar-to-package mapping to package-to-jar mapping.
    """
    data = load_json(jar_to_pkgs_dic)
    pkg_to_jar_mapping = collections.defaultdict(set)
    
    for key, value in tqdm(data.items(), desc="Switching key-value pairs"):
        for pkg in value:
            pkg_to_jar_mapping[pkg].add(key)

    # Save the package-to-jar mapping
    serializable_pkg_to_jar_mapping = {k: list(v) for k, v in sorted(pkg_to_jar_mapping.items())}
    with open("./metaDB/metadata/pkg_to_jar_dic.json", 'w') as f:
        json.dump(serializable_pkg_to_jar_mapping, f)


def add_to_dic():
    if os.path.exists("./metaDB/metadata/jar_to_pkgs_dic.json"):
        jar_to_pkgs_dic = load_json("./metaDB/metadata/jar_to_pkgs_dic.json")
    else:
        jar_to_pkgs_dic={}
    
    enlarge_dic(jar_to_pkgs_dic)
    switch_key_value("./metaDB/metadata/jar_to_pkgs_dic.json")


