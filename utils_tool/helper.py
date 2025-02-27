import glob, os, json,pickle
import collections
from tqdm import tqdm
import subprocess
import concurrent.futures

def load_json(file_path):
    with open(file_path, 'r') as f:
        j = json.load(f)
    return j

def dump_json(my_dict, file_path):
    # Assuming logs is your dictionary
    with open(file_path, 'w') as f:
        json.dump(my_dict, f, indent=4)



def get_sbom_files(directory):
    file_list=[]
    search_path = os.path.join(directory, '**/*.pom')
    files = glob.glob(search_path, recursive=True)
    no_found_jar=[]
    for f in files:
        #print(f)
        if "sources.jar" in f or "source.jar" in f:
            continue
        jar_file=f.replace(".pom",".jar")
        if os.path.exists(jar_file):
            file_list.append(jar_file)
        else:
            #print(jar_file)
            no_found_jar.append(jar_file)
    
    print("the length of pom file is {}, the length of jar file is {}".format(len(files),len(file_list)))     
    return file_list


def get_sbom(file):
    jar_name=file.split("/")[-1]
    parent_path=file.split(jar_name)[0]
    search_path = os.path.join(parent_path, '**/*cyclonedx*.json')
    files = glob.glob(search_path, recursive=True)
    if len(files)==0:
        return None
    try:
        sbom=load_json(files[0])
        return sbom
    except:
        print("fail to load sbom")
        return None


def load_pickle(file):
    with open(file, 'rb') as f:
        data = pickle.load(f)
    return data

def dump_pickle(my_dict, filename):
    # open the file in write-binary mode
    with open(filename, 'wb') as f:
        # use pickle.dump to dump the dictionary to the file
        pickle.dump(my_dict, f)



def get_meta_data(file):

    dir=file.split("/")[-4]+"/"+file.split("/")[-3]+"/"+file.split("/")[-2]
    metafile="./results/jarpkgtags/"+dir+"/meta_info.json"
    if not os.path.exists(metafile):
        print("metadata is not exsiting")
    try:
        meta_data=load_json(metafile)
        return meta_data
    except:
        print("fail to load meta_data")
        return None
