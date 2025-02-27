import glob,os,json
import collections
from tqdm import tqdm
import xml.etree.ElementTree as ET


def get_sbom_files(directory):
    file_list=[]
    search_path = os.path.join(directory, '**/*cyclonedx*.json')
    files = glob.glob(search_path, recursive=True)
    for f in files:
        print(f)
        file_list.append(f)
    print(len(files))
    return file_list


def load_json(file_path):
    with open(file_path, 'r') as f:
        sbom = json.load(f)
    return sbom


def get_all_sbom_deps(sbom_path):
    components_dic=collections.defaultdict(int)
    sbom = load_json(sbom_path)
    if "components"  in sbom.keys():
        for c in sbom["components"]:
            components_dic[c["purl"]]+=1

    if "dependencies" in sbom.keys():
        for dependency in sbom["dependencies"]:
            if "dependsOn" not in dependency.keys():
                continue
            for purl in dependency["dependsOn"]:
                components_dic[purl]+=1
        
    sorted_dict = dict(sorted(components_dic.items(), key=lambda item: item[1],reverse=True))
    return sorted_dict


def trans_purl(purl):
    # split the purl string by '/' and '@' to extract the relevant parts
    parts = purl.split('/')
    #print(parts)
    group_id = parts[1]
    artifact_id =parts[2].split('@')[0]
    version = parts[2].split('@')[1].split('?')[0]
    return f"{group_id}|{artifact_id}|{version}"




def parse_pom(file):
    deps=[]
    # Define the namespaces
    namespaces = {
        'default': 'http://maven.apache.org/POM/4.0.0'
    }
    
    # Register the namespaces
    ET.register_namespace('', namespaces['default'])
    
    # Parse the XML file
    tree = ET.parse(file)
    root = tree.getroot()
    
    # Iterate over dependencies
    for dependency in root.findall(".//default:dependency", namespaces):
        groupId = dependency.find('default:groupId', namespaces)
        artifactId = dependency.find('default:artifactId', namespaces)
        version = dependency.find('default:version', namespaces)
        
        # Print the dependency information
        deps.append((groupId, artifactId, version))
    return deps



def get_pom_files(directory):
    file_list=[]
    search_path = os.path.join(directory, '**/*.pom')
    files = glob.glob(search_path, recursive=True)
    for f in files:
        print(f)
        file_list.append(f)
    print(len(files))
    return file_list



def get_all_pom_deps(file_list):
    components_dic=collections.defaultdict(int)
    for f in tqdm(file_list):
        deps=parse_pom(f)
        for dep in deps:
            groupID=dep[0].text if dep[0] is not None else ""
            artifactId=dep[1].text if dep[1] is not None else ""
            version=dep[2].text if dep[2] is not None else ""
            identity=f"{groupID}|{artifactId}|{version}"
            components_dic[identity]+=1
    sorted_dict = dict(sorted(components_dic.items(), key=lambda item: item[1],reverse=True))
    return sorted_dict



def get_directories(path):
    return [path+"/"+d for d in os.listdir(path) if os.path.isdir(os.path.join(path, d))]



        
def extract_sbom_deps(sbom_path):

    components_dic=get_all_sbom_deps(sbom_path)
    print(len(components_dic))
    #with open("./analysis_result/purl.json", 'w') as f:
        #json.dump(components_dic, f)
    
    new_dict = {trans_purl(key): value for key, value in components_dic.items()}
    #with open("./data/sbom_deps.json", 'w') as f:
        #json.dump(new_dict, f)
    return new_dict



def construct_transitive_deps_download_list(sbom_path):
    sbom_dep=extract_sbom_deps(sbom_path)
    download_dep_list=set()
    for item in sbom_dep:
        download_dep_list.add(item)
    return list(download_dep_list)



if __name__ == '__main__':
    sbom_path="./samples/aaa-cli-jar-0.15.2/aaa-cli-jar-0.15.2-cyclonedx.json"
    download_dep_list=construct_transitive_deps_download_list(sbom_path)
    print(download_dep_list)


    
    

    
   



    