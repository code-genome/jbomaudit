import glob, os, json
import collections
from tqdm import tqdm
import subprocess
import concurrent.futures



def run_jar_pkg_tags(file):
    """
    Runs the `jarpkgtags` command on a specified JAR file to generate metadata.

    This function processes a JAR file and saves the output metadata in a JSON file. 
    The directory structure of the output file mirrors the source file path but stores 
    it under a results directory.
    """

    jar_name=file.split("/")[-1]
    if "/metaDB/maven_asset_deps/" in file:
        parent_path=file.split(jar_name)[0].replace("/metaDB/maven_asset_deps/","/results/jarpkgtags/")
    else:
        parent_path=file.split(jar_name)[0].replace("/samples/","/results/jarpkgtags/")

    if not os.path.exists(parent_path):
        os.makedirs(parent_path)
    output_file=parent_path+"meta_info.json"
    # specify your command
    #print(output_file)
    if os.path.exists(output_file):
        #print("existing!")
        return
    command = f"jarpkgtags {file}"
    # run the command
    process = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
    output, error = process.communicate()

    # open a file and write the output
    with open(output_file, 'wb') as file:
        file.write(output)



def get_sub_dir(current_directory):
    # List all subdirectories using os.listdir
    sub_dir=[]
    for name in os.listdir(current_directory):
        if os.path.isdir(os.path.join(current_directory, name)):
            sub_dir.append(os.path.join(current_directory, name))
    return sub_dir



def get_shortest_jar(directory):
    file_list=[]
    gid_dirs=get_sub_dir(directory)
    for gid_dir in gid_dirs:
        aid_dirs=get_sub_dir(gid_dir)
        for aid_dir in aid_dirs:
            vid_dirs=get_sub_dir(aid_dir)
            for vid_dir in vid_dirs:
                #print(vid_dir)
                search_path = os.path.join(vid_dir, '**/*.jar')
                jar_list = glob.glob(search_path, recursive=True)
                if len(jar_list)==0:
                    continue
                shortest_filename = min(jar_list, key=len)
                file_list.append(shortest_filename)
    return file_list





def batch_process(file_list):
    """
    Processes a list of JAR files in parallel, generating metadata for each file.

    Args:
        file_list (list): List of paths to JAR files to process.
    """
    with concurrent.futures.ThreadPoolExecutor() as executor:
        list(tqdm(executor.map(run_jar_pkg_tags, file_list), total=len(file_list)))


def generate_pkgs_for_sbom():
    """
    Generates package tags for JAR files in the SBOM directory by finding and processing each file.
    """
    file_list=get_shortest_jar(directory='./samples/')
    batch_process(file_list)



def generate_pkgs_for_sbom_deps():
    """
    Generates package tags for JAR files in the SBOM dependencies directory by finding and processing each file.
    """
    file_list=get_shortest_jar(directory='./metaDB/maven_asset_deps/')
    batch_process(file_list)

def generate_jarpkgtags():
    generate_pkgs_for_sbom()
    generate_pkgs_for_sbom_deps()



if __name__ == '__main__':
    generate_pkgs_for_sbom()
    generate_pkgs_for_sbom_deps()





