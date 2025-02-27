import time
import time
import collections
import requests
import os,json,glob
import requests
from bs4 import BeautifulSoup
from tqdm import tqdm


skip=[".asc",".md5",".sha256",".sha512","-javadoc.",".sha1",".source",".sources","source","-tests"]


def skip_check(link):
    for term in skip:
        if term in str(link).lower():
            return True
    return False


def download_maven_artifacts(groupId, artifactId, version, dic_path):

    group_path = groupId.replace(".", "/")

    base_url = "https://repo1.maven.org/maven2/"
    artifact_folder_url = f"{base_url}{group_path}/{artifactId}/{version}/"

    # Get the HTML content of the directory
    response = requests.get(artifact_folder_url)
    if response.status_code != 200:
        print("Error accessing artifact folder:", response.status_code)
        #f=open("./log/error.log","a+")
        #f.write("Error accessing artifact folder:"+artifact_folder_url+"\n")
        #f.close()
        return
    


    # Parse the HTML
    soup = BeautifulSoup(response.text, 'html.parser')

    # Find all links in the HTML
    links = soup.find_all('a')

    # Filter the links to get only the files (ignore directory navigation links)
    file_links = [link['href'] for link in links if not link['href'].endswith('/')]


    if not os.path.exists(dic_path):
        os.makedirs(dic_path)

        #save the response into html
    with open(dic_path+"response.html", "w", encoding="utf-8") as file:
        # Write the response content to the file
        file.write(response.text)


    DONWLOAD=0
    for file_link in file_links:
        file_url = artifact_folder_url + file_link

        if skip_check(file_url):
            continue

        if ".jar" not in file_link:
            continue
            
        if ".source" in file_link:
            continue

        if ".sources" in file_link:
            continue

        if os.path.exists(dic_path+file_link):
            print("file exist!"+dic_path+file_link+"\n")
            #f=open("./log/error.log","a+")
            #f.write("file exist!"+dic_path+file_link+"\n")
            #f.close()
            continue

        response = requests.get(file_url)
        DONWLOAD=1
        
        if response.status_code == 200:
            with open(dic_path+file_link, 'wb') as f:
                f.write(response.content)
            print(f"Downloaded: {file_link}")
            #f=open("./log/transitive_success.log","a+")
            #f.write(dic_path+file_link +"\n")
            #f.close()
        else:
            print("Error downloading file:", response.status_code)
            #f=open("./log/error.log","a+")
            #f.write(file_url +"\n")
            #f.close()
    if DONWLOAD==0:
        #f=open("./log/error.log","a+")
        #f.write("No jar found:" + f'{groupId}|{artifactId}|{version}' +"\n")
        #f.close()
        print("No jar found:" + f'{groupId}|{artifactId}|{version}' +"\n")

def load_json(file_path):
    with open(file_path, 'r') as f:
        pkg = json.load(f)
    return pkg    

