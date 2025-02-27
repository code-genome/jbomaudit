from crawl_deps import crawl_assets
from generate_jar_pkg_tags import generate_jarpkgtags
from add_jar_to_pkg_dic import add_to_dic 
from compliance_check import check_sbom_noncompliance
import argparse
import os

# Define available search modes
class SearchMode:
    GLOBAL = "global"
    LAYER = "layer"

def audit(sbom_path, jar_path, mode):
    """
    Perform SBOM and JAR auditing based on the selected mode.
    """
    # Step 1: Download all dependencies
    root_path = "./metaDB/maven_asset_deps/"
    if not os.path.exists(root_path):
        os.makedirs(root_path)
    crawl_assets(sbom_path, root_path)

    # Step 2: Run jarpkgtags to generate metadata and add to dictionary if not already stored
    generate_jarpkgtags()
    add_to_dic()
    
    # Step 3: Check for non-compliance issues
    check_sbom_noncompliance(sbom_path, jar_path, mode)


if __name__ == '__main__':
    # Initialize the argument parser
    parser = argparse.ArgumentParser(description="Run the SBOM and JAR audit tool.")

    # Add arguments for SBOM path and JAR path
    parser.add_argument('--sbom_path', type=str, required=True, help="Path to the SBOM JSON file")
    parser.add_argument('--jar_path', type=str, required=True, help="Path to the JAR file")

    # Add the mode argument with default set to GLOBAL
    parser.add_argument('-m', '--mode', type=str, choices=[SearchMode.GLOBAL, SearchMode.LAYER], 
                        default=SearchMode.GLOBAL, help="Comparison mode: 'global' (default) or 'layer'")

    # Parse the arguments from the command line
    args = parser.parse_args()

    # Pass the command-line arguments to the audit function
    audit(args.sbom_path, args.jar_path, args.mode)
