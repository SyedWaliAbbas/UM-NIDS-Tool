import os
import re
import pandas as pd
from tqdm import tqdm

# Function to clean the file name by removing digits and '_processed' for attack name
def get_attack_name(filename):
    # Remove digits and '_processed' from the file name
    attack_name = re.sub(r'\d+', '', os.path.splitext(filename)[0])
    attack_name = attack_name.replace('_processed', '')
    return attack_name

# Function to process each CSV file
def process_csv_file(file_path, attacker_mac):
    df = pd.read_csv(file_path, low_memory=False)
    df.columns = df.columns.str.replace(' ', '')
    df.columns = df.columns.str.lower()

    # Check if the file is benign or an attack
    filename = os.path.basename(file_path)
    if 'benign' in filename.lower():
        # For benign files, filter out attacker MACs and label the rest as benign
        df_filtered = df[~df['src_mac'].isin(attacker_mac) & ~df['dst_mac'].isin(attacker_mac)]
        df_filtered['label'] = 'benign'
    else:
        # For attack files, label instances with attacker MACs as an attack
        df_filtered = df[df['src_mac'].isin(attacker_mac) | df['dst_mac'].isin(attacker_mac)]
        attack_name = get_attack_name(filename)
        df_filtered['label'] = attack_name

    return df_filtered

# Function to process all CSV files in a folder
def process_csv_with_attacker_macs(folder_path, output_file,attacker_mac):
    all_dfs = []

    # Iterate over all CSV files in the folder
    for filename in tqdm(os.listdir(folder_path), desc="Processing CSV files"):
        if filename.endswith(".csv"):
            file_path = os.path.join(folder_path, filename)
            try:
                df_labeled = process_csv_file(file_path, attacker_mac)
                all_dfs.append(df_labeled)
                print(f"Processed and labeled {filename}: Label = {df_labeled['label'].unique()}")
            except Exception as e:
                print(f"Failed to process {filename}: {e}")

    # Aggregate all dataframes into one
    combined_df = pd.concat(all_dfs, ignore_index=True)

    # Write the final aggregated dataset to a CSV file
    combined_df.to_csv(output_file, index=False)
    print(f"Aggregated dataset saved to {output_file}")



