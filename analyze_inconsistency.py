import glob, os, json,pickle
import collections
from tqdm import tqdm
import subprocess
import concurrent.futures
from utils_tool.helper import *
import networkx as nx
from collections import defaultdict




class BomGraph:
    """
    Represents a Software Bill of Materials (SBOM) graph structure.

    Attributes:
        file (str): Path to the SBOM file.
        sbom_json (dict): Parsed JSON content of the SBOM file.
        sbom_graph (DiGraph): Directed graph representing dependencies.
        root_node (str): Root node of the SBOM dependency graph.
        sbom_dir_deps (list): Direct dependencies from the SBOM.
        sbom_second_deps (list): Second-level dependencies from the root.
        various_logs (dict): Containers for logging missing and incorrect dependencies.
    """
    def __init__(self, file):
        self.file = file
        self.sbom_json = get_sbom(file)
        self.sbom_graph = get_sbom_dependency_relationship(self.sbom_json)  
        self.root_node = [node for node, degree in  self.sbom_graph.in_degree() if degree == 0][0]
        self.sbom_dir_deps = get_sbom_direct_deps(self.sbom_graph)
        self.sbom_second_deps=self.sbom_graph.successors(self.root_node)
        self.missing_log={"missing_deps": {}} 
        self.incorrect_log = {"incorrect_deps": defaultdict(dict)}
        self.incorrect_transitive_deps_log = {"incorrect_transitive_deps": []} 
        self.incorrect_transitive_relationship_log = {"incorrect_transitive_relationship": []} 
        self.missing_transitive_dependency_log={"missing_transitive_dependency":[]}
        self.missing_transitive_relationship_log={"missing_transitive_relationship":[]}
        self.uncollected_log={"first_level":[],"second_level":defaultdict(dict)}
        self.unresolved_dynamic={"first_level":defaultdict(dict),"second_level":defaultdict(dict)}
        # Load pre-existing mappings for packages and JARs
        self.jar_to_pkgs_dic=load_json("./metaDB/metadata/jar_to_pkgs_dic.json")
        self.all_disclosed_deps=[purl_to_aid_gid_vid(n) for n in self.sbom_graph.nodes()]
        self.mode="global"




def purl_to_aid_gid_vid(purl):
    """
    Parses a package URL (purl) to extract the group ID, artifact ID, and version ID.
    
    Args:
        purl (str): Package URL containing metadata.
        
    Returns:
        str: Concatenated string with group ID, artifact ID, and version ID.
    """
    referenceLocator=purl.replace("?type=jar","")
    gid=referenceLocator.split("/")[1]
    aid=referenceLocator.split("/")[2].split("@")[0]
    vid=referenceLocator.split("@")[-1]
    if "?" in vid:
        vid=vid.split("?")[0]
    return f'{gid}|{aid}|{vid}'


def get_sbom_dependency_relationship(sbom):
    """
    Constructs a directed graph of dependencies from the SBOM data.
    
    Args:
        sbom (dict): Parsed JSON of SBOM content.
        
    Returns:
        DiGraph: Directed graph representing dependency relationships.
    """
    G = nx.DiGraph()
    if sbom is None:
        return G
    if "dependencies" not in sbom.keys():
        return G
    
    for dependency in sbom["dependencies"]:
        ref = dependency['ref']
        depends_on = dependency.get('dependsOn', [])
        if len(depends_on)==0:
            G.add_node(ref)
        for dep in depends_on:
            # Add a directed edge from ref to each dependency in dependsOn
            G.add_edge(ref, dep)
    return G


def get_sbom_direct_deps(G):
    """
    Retrieves direct dependencies (first-level dependencies) from the SBOM graph.
    
    Args:
        G (DiGraph): Directed graph of SBOM dependencies.
        
    Returns:
        list: List of package IDs for direct dependencies.
    """
    root_nodes = [node for node, degree in G.in_degree() if degree == 0]
    if len(root_nodes)!=1:
        return []
    root_children = list(G.successors(root_nodes[0]))
    return [purl_to_aid_gid_vid(c) for c in root_children]



#Skip the classes from JDK which are not considered as external dependencies
def skip(item):
    skip_list=["java.","javax.","sun.misc","org.xml.sax","sun.nio.ch","org.w3c.dom","com.sun."]
    for pre in skip_list:
        if item.startswith(pre):
            return True
    return False



def get_all_usage_pkg(meta_json):
    """
    Extracts all internal and external packages used from metadata.
    
    Args:
        meta_json (dict): Metadata JSON containing package information.
        
    Returns:
        list: List of unique external package usages.
    """
    #get all internal pkg
    if meta_json is None:
        print("error: can not get internal package info")
        return 
    provided_internal_pkg=[]
    if "packages" in meta_json.keys():
        for pkg in meta_json["packages"]:
            if len(pkg)==0:
                continue
            provided_internal_pkg.append(pkg)
    

    #get all external used pkg
    usage=[]
    for pkg in meta_json["packages"]:
        if len(pkg)==0:
            continue
        for u in meta_json["packages"][pkg]["uses"]:
            #filter our if the pkg is internal usage
            if u in provided_internal_pkg or skip(u):
                continue
            usage.append(u)
        
        if "reflected" in meta_json["packages"][pkg].keys():
            for r in meta_json["packages"][pkg]["reflected"]:
                if r in provided_internal_pkg or skip(r):
                    continue
                usage.append(r)

    return list(set(usage))


def get_unresolved_dynamic(meta_json):
    """
    Retrieves dynamically unresolved packages from metadata.
    
    Args:
        meta_json (dict): Metadata JSON containing package information.
        
    Returns:
        list: List of unresolved dynamic packages.
    """
    unresolved_dynamic=[]
    for pkg in meta_json["packages"]:
        if "unresolved_dynamic" in meta_json["packages"][pkg].keys():
            unresolved_dynamic.extend(meta_json["packages"][pkg]["unresolved_dynamic"])
    return unresolved_dynamic



def has_overlap(list1, list2):
    """
    Checks if there is any overlap between two lists, based on prefix.
    
    Args:
        list1, list2 (list): Lists of items to compare.
        
    Returns:
        bool: True if there is overlap, False otherwise.
    """
    new_list1=[item.split("|")[0] for item in list1]
    new_list2=[item.split("|")[0] for item in list2]

    return bool(set(new_list1) & set(new_list2))



def get_sbom_second_level_nodes(G):
    """
    Retrieves second-level dependencies from the SBOM dependency graph.

    Args:
        G (DiGraph): Directed graph of SBOM dependencies.

    Returns:
        list: List of package IDs for second-level dependencies, or an empty list if there is an issue.
    """
    root_nodes = [node for node, degree in G.in_degree() if degree == 0]
    if len(root_nodes)!=1:
        return []
    root_children = list(G.successors(root_nodes[0]))
    third_level_nodes=[]
    for c in root_children:
        third_level_nodes.extend()
    return [purl_to_aid_gid_vid(c) for c in root_children]


def get_meta_info(node_l2):
    """
    Retrieves metadata information for a second-level dependency node.

    Args:
        node_l2 (str): Node identifier for the second-level dependency.

    Returns:
        dict or None: Loaded JSON metadata if found, otherwise None.
    """
    root_path="./results/jarpkgtags/"
    relative_path=purl_to_aid_gid_vid(node_l2).replace("|","/")
    full_path=root_path+relative_path+"/"+"meta_info.json"

    if os.path.exists(full_path):
        try:
            meta_data=load_json(full_path)
            return meta_data
        except:
            print("fail to load meta_data")
            return None
    return None


def detect_missing_dependency(bomGraph):
    """
    Detects missing dependencies by comparing SBOM and actual usage information.

    Args:
        bomGraph (BomGraph): Instance of BomGraph representing the SBOM graph and data.
    """
    if bomGraph.sbom_json is None:
        return 
    meta_json = get_meta_data(bomGraph.file)
    all_usage = get_all_usage_pkg(meta_json)
    #print("sbom_dir_deps is {}".format(len(set(bomGraph.sbom_dir_deps))))

    if bomGraph.mode ==  "global":
        print("Performing whole tree search")
        all_provided_packages=get_all_provided_packages(bomGraph, bomGraph.all_disclosed_deps)

    elif bomGraph.mode == "layer":
        print("Performing layer search")
        all_provided_packages=get_all_provided_packages(bomGraph, bomGraph.sbom_dir_deps)
    
    for usage in all_usage:
        if usage not in all_provided_packages:
            bomGraph.missing_log["missing_deps"][usage] = []

        '''
        jars = pkg_to_jar_dic.get(usage, [])
        if len(jars) > 0 and not has_overlap(jars, bomGraph.sbom_dir_deps):
            # Determine if it is mentioned in transitive dependencies
            bomGraph.missing_log["missing_deps"][usage] = list(jars)
        '''


def detect_incorrect_dependency(bomGraph):
    """
    Identifies incorrect dependencies by analyzing SBOM entries against actual usage.

    Args:
        bomGraph (BomGraph): Instance of BomGraph representing the SBOM graph and data.
    """
    if bomGraph.sbom_json==None:
        return 
    incorrect_deps=set()
    meta_json=get_meta_data(bomGraph.file)
    all_usage=get_all_usage_pkg(meta_json)

    for dep in  bomGraph.sbom_dir_deps:
        if dep not in bomGraph.jar_to_pkgs_dic.keys():
            incorrect_deps.add(dep)
            continue
        dep_pkgs= bomGraph.jar_to_pkgs_dic[dep]
        if len(all_usage) >0 and len(dep_pkgs) > 0 and not has_overlap(all_usage, dep_pkgs):
            bomGraph.incorrect_log["incorrect_deps"][dep]["provided_packages"]=list(dep_pkgs)
    
    #record potential causes of FP or FN
    bomGraph.uncollected_log["first_level"]=list(incorrect_deps)
    unresolved = get_unresolved_dynamic(meta_json)
    if len(unresolved)!=0:
        bomGraph.unresolved_dynamic["first_level"][purl_to_aid_gid_vid(bomGraph.root_node)]=unresolved
    


def detect_incorrect_transitive_dependency(bomGraph):
    """
    Detects incorrect transitive dependencies in the SBOM dependency graph.

    Args:
        bomGraph (BomGraph): Instance of BomGraph representing the SBOM graph and data.
    """
    if bomGraph.sbom_json is None:
        return   
    
    for node_l2 in bomGraph.sbom_second_deps:
        uncollected=[]
        node_l2_=purl_to_aid_gid_vid(node_l2)
        meta_json=get_meta_info(node_l2)
        if meta_json == None:
            continue

        all_usage=get_all_usage_pkg(meta_json)
        for node_l3 in list(bomGraph.sbom_graph.successors(node_l2)):
            #check any used packages in node_l2 is provided by node node_l3
            node_l3_=purl_to_aid_gid_vid(node_l3)
            if node_l3_ not in bomGraph.jar_to_pkgs_dic.keys():
                uncollected.append(node_l3_)
                continue
            dep_pkgs= bomGraph.jar_to_pkgs_dic[node_l3_]
            if len(all_usage) >0 and len(dep_pkgs) > 0 and not has_overlap(all_usage, dep_pkgs):
                record={}
                record["from"]=node_l2_
                record["to"]=node_l3_
                if bomGraph.sbom_graph.in_degree(node_l3)<=1:
                    bomGraph.incorrect_transitive_deps_log["incorrect_transitive_deps"].append(record)
                #node_l3 has two or more parents
                else:
                    bomGraph.incorrect_transitive_relationship_log["incorrect_transitive_relationship"].append(record)
        unresolved=get_unresolved_dynamic(meta_json)
        if len(unresolved)!=0:
            bomGraph.unresolved_dynamic["second_level"][node_l2_]=unresolved
        bomGraph.uncollected_log["second_level"][node_l2_]=uncollected
    


def check_missing_node_has_other_parent(bomGraph,node_l2,usage):
    """
    Checks if a node with missing dependencies has another parent in the graph.

    Args:
        bomGraph (BomGraph): Instance of BomGraph representing the SBOM graph and data.
        node_l2 (str): Node identifier for the second-level dependency.
        usage (list): package used in the node_l2.

    Returns:
        bool: True if the used package has another parent, False otherwise.
    """
    #collect other nodes' children
    child_node_l3=[]
    for n2 in bomGraph.sbom_second_deps:
        if n2==node_l2:
            continue
        child_node_l3.extend([purl_to_aid_gid_vid(n) for n in list (bomGraph.sbom_graph.successors(n2))])

        #get all usages from child_node_l3
        provided_packages=get_all_provided_packages(bomGraph,child_node_l3)
    
    if usage in provided_packages:
        return True
    else:
        return False


def get_all_provided_packages(bomGraph,nodes):
    provided_packages=[]
    for node in nodes:
        pkgs=bomGraph.jar_to_pkgs_dic.get(node,[])
        provided_packages.extend(pkgs)
    return provided_packages



def detect_missing_transitive_dependency(bomGraph):
    """
    Detects missing transitive dependencies in the SBOM dependency graph.

    Args:
        bomGraph (BomGraph): Instance of BomGraph representing the SBOM graph and data.
    """
    if bomGraph.sbom_json is None:
        return   
    for node_l2 in bomGraph.sbom_second_deps:
        meta_json=get_meta_info(node_l2)
        if meta_json == None:
            continue
        
        #get all used packages in node_l2
        all_usage=get_all_usage_pkg(meta_json)
        node_l2_=purl_to_aid_gid_vid(node_l2)

        #get provided packages from all third-level nodes
        sbom_third_level_nodes=[purl_to_aid_gid_vid(n) for n in list(bomGraph.sbom_graph.successors(node_l2))]

        if bomGraph.mode ==  "global":
            print("Performing whole tree search")
             # check whether each used package are provided by any nodes in the tree
            provided_packages=get_all_provided_packages(bomGraph, bomGraph.all_disclosed_deps)

        elif bomGraph.mode == "layer":
            print("Performing layer search")
            # check whether each used package are provided by any third-level nodes
            provided_packages=get_all_provided_packages(bomGraph, sbom_third_level_nodes)

        for usage in all_usage:
            if usage not in provided_packages:
                record={}
                record["node_l2"]=node_l2_
                record["usage"]=usage
                record["missing_deps"]=[]
                if not check_missing_node_has_other_parent(bomGraph,node_l2,usage):
                    bomGraph.missing_transitive_dependency_log["missing_transitive_dependency"].append(record)
                else:
                    bomGraph.missing_transitive_relationship_log["missing_transitive_relationship"].append(record)

            
            '''
            if len(jars) > 0 and not has_overlap(jars, sbom_third_level_nodes):
                record={}
                record["node_l2"]=node_l2_
                record["usage"]=usage
                record["missing_deps"]=list(jars)
                if not check_missing_node_has_other_parent(bomGraph,node_l2,jars):
                    bomGraph.missing_transitive_dependency_log["missing_transitive_dependency"].append(record)
                else:
                    bomGraph.missing_transitive_relationship_log["missing_transitive_relationship"].append(record)
            '''




def check_missing_and_incorrect_deps(bomGraph):
    """
    Runs all detection methods to identify missing and incorrect dependencies.

    Args:
        bomGraph (BomGraph): Instance of BomGraph representing the SBOM graph and data.
    """
    detect_missing_dependency(bomGraph)
    detect_incorrect_dependency(bomGraph)
    detect_incorrect_transitive_dependency(bomGraph)
    detect_missing_transitive_dependency(bomGraph)




def build_nested_dict(graph, node):
    """ Recursively build a nested dictionary for each node and its children """
    return {n: build_nested_dict(graph, n) for n in graph.neighbors(node)}



def analyze_inconsistency(file, to_graph,to_result,mode):
    """
    Analyzes inconsistencies in an SBOM graph, identifying missing and incorrect dependencies.

    Args:
        file (str): Path to the SBOM file.
        to_graph (str): Path to save the graph structure as JSON.
        to_result (str): Path to save the results as JSON.
    """
    bomGraph=BomGraph(file)
    bomGraph.mode=mode
    check_missing_and_incorrect_deps(bomGraph)
    result={}
    result["missing_log"]= bomGraph.missing_log
    result["incorrect_log"]= bomGraph.incorrect_log
    result["incorrect_transitive_deps_log"]= bomGraph.incorrect_transitive_deps_log
    result["incorrect_transitive_relationship_log"]= bomGraph.incorrect_transitive_relationship_log
    result["missing_transitive_dependency_log"]= bomGraph.missing_transitive_dependency_log
    result["missing_transitive_relationship_log"]= bomGraph.missing_transitive_relationship_log
    result["uncollected"]= bomGraph.uncollected_log
    result["unresolved"]= bomGraph.unresolved_dynamic
   
    with open(to_result, 'w') as json_file:
        json.dump(result, json_file, indent=4)

    
    if not os.path.exists(to_graph):
        nested_dict = build_nested_dict(bomGraph.sbom_graph, bomGraph.root_node)
        with open(to_graph, 'w') as json_file:
            json.dump(nested_dict, json_file, indent=4)


