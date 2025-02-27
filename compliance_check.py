import glob, os, json,pickle
import collections
from tqdm import tqdm
import subprocess
import concurrent.futures
import sys
from utils_tool.helper import *
import networkx as nx
from collections import defaultdict
from analyze_inconsistency import analyze_inconsistency
import shutil
import zipfile
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from tabulate import tabulate






class Validation:
    """
    Handles validation of SBOM dependencies for various types of compliance checks.

    Attributes:
        work_path (str): Working directory path.
        unjar_dir (str): Directory where JAR contents are extracted.
        uncollected (dict): Uncollected dependencies.
        unresolved (dict): Unresolved dependencies.
        validate_missing_log (dict): Log for missing dependencies validation.
        validate_incorrect_log (dict): Log for incorrect dependencies validation.
        validate_incorrect_transitive_deps_log (dict): Log for incorrect transitive dependencies validation.
        validate_incorrect_transitive_relationship_log (dict): Log for incorrect transitive relationship validation.
        validate_missing_transitive_dependency_log (dict): Log for missing transitive dependencies validation.
        validate_missing_transitive_relationship_log (dict): Log for missing transitive relationships validation.
    """

    def __init__(self, work_path, unjar_dir, uncollected, unresolved):
        self.work_path = work_path
        self.unjar_dir = unjar_dir
        self.uncollected = uncollected
        self.unresolved = unresolved
        self.validate_missing_log = {"validate_missing_deps": defaultdict(dict)}
        self.validate_incorrect_log = {"validate_incorrect_deps": defaultdict(dict)}
        self.validate_incorrect_transitive_deps_log = {"validate_incorrect_transitive_deps": []}
        self.validate_incorrect_transitive_relationship_log = {"validate_incorrect_transitive_relationship": []}
        self.validate_missing_transitive_dependency_log = {"validate_missing_transitive_dependency": []}
        self.validate_missing_transitive_relationship_log = {"validate_missing_transitive_relationship": []}
        self.jar_to_pkgs_dic=load_json("./metaDB/metadata/jar_to_pkgs_dic.json")


def is_existed(classname, unjar_dir):
    command = ["grep", "-r", classname, unjar_dir]
    # Run the command and capture the output
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if "Binary file" in result.stdout and ".class" in result.stdout:
        return True,result
    else:
        return False,result



def valid_missing_log(missing_log,vail):
    """
    Validates missing dependencies by checking if they exist in uncollected dependencies.
    
    Args:
        missing_log (dict): Log of missing dependencies.
        vail (Validation): Validation object to store results.
    """
    vail.validate_missing_log["uncollected_first_level"]=vail.uncollected["first_level"]
    for used_class in missing_log["missing_deps"].keys():
        existing_flag,result=is_existed(used_class,  vail.unjar_dir)
        if existing_flag:
            if len(vail.validate_missing_log["uncollected_first_level"])==0:
                vail.validate_missing_log["validate_missing_deps"][used_class]["flag"]="true"
                vail.validate_missing_log["validate_missing_deps"][used_class]["proof"]=result.stdout
            else:
                vail.validate_missing_log["validate_missing_deps"][used_class]["flag"]="Undetermined"
                vail.validate_missing_log["validate_missing_deps"][used_class]["proof"]=result.stdout
 

def valid_incorrect_log(incorrect_log,vail):   
    """
    Validates incorrect dependencies by checking their existence in provided packages.
    
    Args:
        incorrect_log (dict): Log of incorrect dependencies.
        vail (Validation): Validation object to store results.
    """
    vail.validate_incorrect_log["unresolved_first_level"]=vail.unresolved["first_level"]
    for incorrect_dep in incorrect_log["incorrect_deps"]:
        existing_list={}
        not_existing_list={}
        for classname in incorrect_log["incorrect_deps"][incorrect_dep]["provided_packages"]:
            if len(classname)==0:
                continue
            existing_flag,result=is_existed(classname,  vail.unjar_dir)
            if existing_flag:
                existing_list[classname]=result.stdout
            else:
                not_existing_list[classname]=result.stdout
                
        if existing_list: 
            pass
            #vail.validate_incorrect_log["validate_incorrect_deps"][incorrect_dep]["flag"]="false"
            #vail.validate_incorrect_log["validate_incorrect_deps"][incorrect_dep]["proof"]=existing_list
        else:
            if vail.unresolved["first_level"]:
                vail.validate_incorrect_log["validate_incorrect_deps"][incorrect_dep]["flag"]="Undetermined"
                vail.validate_incorrect_log["validate_incorrect_deps"][incorrect_dep]["proof"]=not_existing_list
            else:
                vail.validate_incorrect_log["validate_incorrect_deps"][incorrect_dep]["flag"]="true"
                vail.validate_incorrect_log["validate_incorrect_deps"][incorrect_dep]["proof"]=not_existing_list




def get_shortest_jar(directory):
    search_path = os.path.join(directory, '*.jar')
    jar_list = glob.glob(search_path, recursive=True)
    if len(jar_list)==0:
        return None
    shortest_filename = min(jar_list, key=len)
    return shortest_filename

def create_search_workspace(from_,vail):
    """
    Creates a workspace for analyzing dependencies by unzipping a JAR file.
    
    Args:
        from_ (str): Package path to retrieve the JAR.
        vail (Validation): Validation object with working paths.
        
    Returns:
        str: Directory path where JAR contents are extracted.
    """
    from_dir="./metaDB//maven_asset_deps/" + from_.replace("|","/")+"/"
    from_jar_path=get_shortest_jar(from_dir)
    jar_name=os.path.basename(from_jar_path)
    current_dir=vail.work_path+"deps/"+jar_name+"/"
    search_dir=current_dir+"unjar/"

    #reduce replicated copy operations
    if os.path.exists(search_dir):
        return search_dir
    else:
        os.makedirs(current_dir,exist_ok=True)
        shutil.copy(from_jar_path, current_dir)
        
        os.makedirs(search_dir,exist_ok=True)
        with zipfile.ZipFile(current_dir+jar_name, 'r') as zip_ref:
            zip_ref.extractall(search_dir)
        return search_dir



def determine_dep_relationship_between_fromDeps_and_toDeps(from_,to_,vail):
    """
    Determines dependency relationships between two dependency.
    
    Args:
        from_ (str): Source dependency.
        to_ (str): Target dependency.
        vail (Validation): Validation object.
        
    Returns:
        dict: Record of the relationship and whether dependencies are resolved.
    """

    #step one: create search workspace and unzip target jar
    search_dir=create_search_workspace(from_,vail)

    #step two: get all provided packages from "to_"
    provided_pkgs= vail.jar_to_pkgs_dic[to_]
    existing_list={}
    not_existing_list={}
    for pkg in provided_pkgs:
        if len(pkg)==0:
            continue
        existing_flag,result = is_existed(pkg, search_dir)
        if existing_flag:
            existing_list[pkg]=result.stdout
        else:
            not_existing_list[pkg]=result.stdout

    #step three: check if any provided packages from "to_" is actually used by "from_"
    record={}
    if existing_list: 
        #record["from"]=from_
        #record["to"]=to_
        #record["flag"]="false"
        #record["proof"]=existing_list
        pass
    else:
        if from_ in vail.unresolved["second_level"].keys() :
            record={}
            record["from"]=from_
            record["to"]=to_
            record["flag"]="Undetermined"
            record["unresolved"]=vail.unresolved["second_level"][from_]
        else:
            record={}
            record["from"]=from_
            record["to"]=to_
            record["flag"]="true"
            record["proof"]=not_existing_list
    return record



def valid_incorrect_transitive_deps_log(incorrect_transitive_dep_log,vail):
    for pair in incorrect_transitive_dep_log["incorrect_transitive_deps"]:
        from_=pair["from"]
        to_=pair["to"]
        record=determine_dep_relationship_between_fromDeps_and_toDeps(from_,to_,vail)
        vail.validate_incorrect_transitive_deps_log["validate_incorrect_transitive_deps"].append(record)


def valid_incorrect_transitive_relationship_log(incorrect_transitive_relationship_log,vail):
    for pair in incorrect_transitive_relationship_log["incorrect_transitive_relationship"]:
        from_=pair["from"]
        to_=pair["to"]
        record=determine_dep_relationship_between_fromDeps_and_toDeps(from_,to_,vail)
        vail.validate_incorrect_transitive_relationship_log["validate_incorrect_transitive_relationship"].append(record)


def valid_missing_transitive_dependency_log(missing_transitive_dependency_log, vail):
    for item_dic in missing_transitive_dependency_log["missing_transitive_dependency"]:
        search_dir=create_search_workspace(item_dic["node_l2"],vail)
        existing_flag,result=is_existed(item_dic["usage"],  search_dir)
        uncollected_deps=vail.uncollected["second_level"][item_dic["node_l2"]] if item_dic["node_l2"] in vail.uncollected["second_level"].keys() else []

        # if didn't find any reference, the missing is false positive
        if not existing_flag:
            pass
            #item_dic["flag"]="false"
            #item_dic["proof"]=result.stdout
        else:
            if len(uncollected_deps)!=0:
                item_dic["flag"]="Undetermined"
                item_dic["proof"]=result.stdout
                item_dic["uncollected"]=uncollected_deps
            else:
                item_dic["flag"]="true"
                item_dic["proof"]=result.stdout
        vail.validate_missing_transitive_dependency_log["validate_missing_transitive_dependency"].append(item_dic)        



def valid_missing_transitive_relationship_log(missing_transitive_relationship_log, vail):
    for item_dic in missing_transitive_relationship_log["missing_transitive_relationship"]:
        search_dir=create_search_workspace(item_dic["node_l2"],vail)
        existing_flag,result=is_existed(item_dic["usage"],  search_dir)
        uncollected_deps=vail.uncollected["second_level"][item_dic["node_l2"]] if item_dic["node_l2"] in vail.uncollected["second_level"].keys() else []

        # if didn't find any reference, the missing is false positive
        if not existing_flag:
            pass
            #item_dic["flag"]="false"
            #item_dic["proof"]=result.stdout
        else:
            if len(uncollected_deps)!=0:
                item_dic["flag"]="Undetermined"
                item_dic["proof"]=result.stdout
                item_dic["uncollected"]=uncollected_deps
            else:
                item_dic["flag"]="true"
                item_dic["proof"]=result.stdout
        vail.validate_missing_transitive_relationship_log["validate_missing_transitive_relationship"].append(item_dic)        



def check_sbom_noncompliance(sbom_path,jar_path,mode):
    """
    Analyzes SBOM and JAR compliance by detecting inconsistencies and validating dependencies.

    This function performs a compliance check on a Software Bill of Materials (SBOM) by comparing it
    to its associated JAR file. It identifies missing and incorrect dependencies at both direct and 
    second transitive levels and logs the findings.

    Args:
        sbom_path (str): Path to the SBOM file.
        jar_path (str): Path to the associated JAR file.

    Workflow:
        1. Generate inconsistency results by analyzing the SBOM graph and logging inconsistencies.
        2. Copy and unzip the JAR file into the evaluation directory for dependency validation.
        3. Run various validation checks for missing and incorrect dependencies.
        4. Save the validation results to a JSON file and display the results in a table.

    Output:
        Creates `compliance_result.json` with validation results and prints a summary table.
    """


    ##step one: generate inconsistency result
  
    root="./results/audit_results/"
    dir=sbom_path.split("/")[-4]+"/"+sbom_path.split("/")[-3]+"/"+sbom_path.split("/")[-2]

 
    #if os.path.exists(root+dir+'/compliance_result.json'):
        #print("existing!")
        #return
    if not os.path.exists(root+dir):
        os.makedirs(root+dir)
    to_graph=root+dir+"/sbom_deps_graph.json"
    to_result=root+dir+"/analyze_log.json"
    #print(sbom_path)
    #print(to_graph)
    analyze_inconsistency(sbom_path, to_graph,to_result,mode)
    
    ##step two: copy jar file in to evaluation dir and unzip it
    shutil.copy(jar_path, root+dir)
    copied_jar=root+dir+"/"+os.path.basename(jar_path)
    unjar_path=root+dir+"/unjar"
    os.makedirs(unjar_path,exist_ok=True)
    with zipfile.ZipFile(copied_jar, 'r') as zip_ref:
        zip_ref.extractall(unjar_path)

    
    #step three 
    work_path=root+dir+"/"
    unjar_path=root+dir+"/unjar"
    inconsistency_log=load_json(to_result)
    vail= Validation(work_path,unjar_path,inconsistency_log["uncollected"],inconsistency_log["unresolved"]) 
    valid_missing_log(inconsistency_log["missing_log"],vail)
    valid_incorrect_log(inconsistency_log["incorrect_log"],vail)
    valid_incorrect_transitive_deps_log(inconsistency_log["incorrect_transitive_deps_log"],vail)
    valid_incorrect_transitive_relationship_log(inconsistency_log["incorrect_transitive_relationship_log"],vail)
    valid_missing_transitive_dependency_log(inconsistency_log["missing_transitive_dependency_log"],vail)
    valid_missing_transitive_relationship_log(inconsistency_log["missing_transitive_relationship_log"],vail)


    # step four: dump the validation result
    Validation_result={}
    Validation_result["M1:Missing Direct Dependency"]= vail.validate_missing_log
    Validation_result["N1:Incorrect Direct Dependency"]= vail.validate_incorrect_log
    Validation_result["N2:Incorrect Transitive Dependency"]= vail.validate_incorrect_transitive_deps_log
    Validation_result["N3:Incorrect Transitive Relationship"] = vail.validate_incorrect_transitive_relationship_log
    Validation_result["M2:Missing Transitive Dependency"] = vail.validate_missing_transitive_dependency_log
    Validation_result["M3: Missing Transitive Relationship"] = vail.validate_missing_transitive_relationship_log
    with open(root+dir+'/compliance_result.json', 'w') as json_file:
        json.dump(Validation_result, json_file, indent=4)

    print("dump successfully {}".format(root+dir+'/compliance_result.json'))
    
    json_transfer_to_table(vail)
    

def json_transfer_to_table(vail):
    non_compliance_type_list=[]
    dep_list=[]
    flag_list=[]
    for d in vail.validate_missing_log["validate_missing_deps"]:
        non_compliance_type_list.append("M1:Missing Direct Dependency")
        dep_list.append(d)
        flag_list.append(vail.validate_missing_log["validate_missing_deps"][d]["flag"])
    
    for d in vail.validate_missing_transitive_dependency_log["validate_missing_transitive_dependency"]:
        non_compliance_type_list.append("M2:Missing Transitive Dependency")
        dep_list.append(d["node_l2"] + " -> " + d["usage"])
        flag_list.append(d["flag"])
        


    for d in vail.validate_missing_transitive_relationship_log["validate_missing_transitive_relationship"]:
        non_compliance_type_list.append("M3: Missing Transitive Relationship")
        dep_list.append(d["node_l2"] + " -> " + d["usage"])
        flag_list.append(d["flag"])


    for d in vail.validate_incorrect_log["validate_incorrect_deps"]:
        non_compliance_type_list.append("N1:Incorrect Direct Dependency")
        dep_list.append(d)
        flag_list.append(vail.validate_incorrect_log["validate_incorrect_deps"][d]["flag"])
    

    for d in vail.validate_incorrect_transitive_deps_log["validate_incorrect_transitive_deps"]:
        if len(d) ==0:
            break
        non_compliance_type_list.append("N2:Incorrect Transitive Dependency")
        dep_list.append(d["from"] + " -> " + d["to"])
        flag_list.append(d["flag"])
    

    for d in vail.validate_incorrect_transitive_relationship_log["validate_incorrect_transitive_relationship"]:
        if len(d) ==0:
            break
        non_compliance_type_list.append("N3:Incorrect Transitive Relationship")
        dep_list.append(d["from"] + " -> " + d["to"])
        flag_list.append(d["flag"])

    # Combine the two lists into a list of rows
    table_data = list(zip(non_compliance_type_list, dep_list,flag_list))

    # Define headers for the table
    headers = ["Non-Compliance Type", "Dependency","Flag"]

    # Pretty print the table using tabulate
    print(tabulate(table_data, headers=headers, tablefmt="grid"))


if __name__ == '__main__':
    sbom_path="./metaDB/maven_asset_sbom/org.opendaylight.aaa/aaa-cli-jar/0.15.2/aaa-cli-jar-0.15.2-cyclonedx.json"
    jar_path= "./metaDB/maven_asset_sbom/org.opendaylight.aaa/aaa-cli-jar/0.15.2/aaa-cli-jar-0.15.2.jar"
    check_sbom_noncompliance(sbom_path,jar_path)
    



    