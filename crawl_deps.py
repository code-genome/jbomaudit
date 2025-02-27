from utils_tool.transitive_download import *
from utils_tool.construct_transitive_deps import construct_transitive_deps_download_list

def crawl_assets(sbom_path,root_path):
    """
    Downloads all dependencies for a given SBOM file from a Maven repository.

    This function reads the dependencies from an SBOM file, constructs the download list,
    and iteratively downloads each dependency if it does not already exist in the specified
    directory structure.

    Args:
        sbom_path (str): Path to the SBOM file.
        root_path (str): Root directory where dependencies will be downloaded and stored.
    Note:
        A sleep interval is used between downloads to prevent overloading the Maven repository.
    """

    deps_file=construct_transitive_deps_download_list(sbom_path)
    for line in deps_file:
        groupId, artifactId, version = line.strip().split('|')
        # Download each file
        dic_path=root_path+ f"{groupId}/{artifactId}/{version}/"
        print(dic_path)
        
        if os.path.exists(dic_path):
            #print("the assets exsit!!!")
            continue
        
        download_maven_artifacts(groupId, artifactId, version, dic_path)
        time.sleep(2)

if __name__ == '__main__':
    sbom_path="./samples/aaa-cli-jar-0.15.2/aaa-cli-jar-0.15.2-cyclonedx.json"
    root_path="./metaDB/maven_asset_deps/"
    crawl_assets(sbom_path,root_path)
