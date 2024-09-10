import os
import pandas as pd
import pytz
from multiprocessing import Pool, set_start_method
import logging
from tqdm import tqdm
from concurrent.futures import ProcessPoolExecutor, as_completed

# Enable logging to capture exceptions and debug information
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Function to process a single CSV file and extract time range
def process_csv_file(args):
    file_path, timestamp_column, timezone, usecols = args
    try:
        # Read CSV file with or without specified columns (usecols)
        df = pd.read_csv(file_path, names=usecols,low_memory=False)
        df.columns = df.columns.str.replace(' ', '')
        df.columns = df.columns.str.lower()

        if timestamp_column in df.columns:
            # Min and Max timestamp
            min_timestamp = df[timestamp_column].min()
            max_timestamp = df[timestamp_column].max()

            # Convert to the desired timezone if provided
            if timezone != 'None':
                datetime_zone = pd.to_datetime(min_timestamp)
                zone_time = pytz.timezone(timezone)
                datetime_zone = zone_time.localize(datetime_zone)
                min_timestamp = datetime_zone.timestamp() * 1000

                datetime_zone = pd.to_datetime(max_timestamp)
                datetime_zone = zone_time.localize(datetime_zone)
                max_timestamp = datetime_zone.timestamp() * 1000
            else:
                # Keep timestamps in milliseconds
                min_timestamp = min_timestamp * 1000
                max_timestamp = max_timestamp * 1000

            logger.info(f"Processed {file_path}: Min timestamp = {min_timestamp}, Max timestamp = {max_timestamp}")
            return {'file_path': file_path, 'min_timestamp': min_timestamp, 'max_timestamp': max_timestamp}
        else:
            logger.warning(f"Column '{timestamp_column}' not found in {file_path}")
            return None
    except Exception as e:
        logger.error(f"Failed to process {file_path}: {e}")
        return None

# Function to extract time ranges from CSVs in multiple folders (parallelized)
def extract_time_ranges_from_csvs(folders, timestamp_column='timestamp', timezone='Canada/Atlantic', batch_size=10, usecols=None):
    time_ranges = []
    
    # Get all CSV file paths from all folders
    all_csv_files = []
    for folder_path in folders:
        if os.path.exists(folder_path):
            for filename in os.listdir(folder_path):
                if filename.endswith(".csv"):
                    file_path = os.path.join(folder_path, filename)
                    all_csv_files.append(file_path)
    
    # Split into batches to avoid memory overload
    def chunked_iterable(iterable, size):
        for i in range(0, len(iterable), size):
            
            yield iterable[i:i + size]

    try:
        with Pool() as pool:
            for csv_batch in chunked_iterable(all_csv_files, batch_size):
                # Process CSV files in parallel with a batch
                args = [(file_path, timestamp_column, timezone, usecols) for file_path in csv_batch]
                results = pool.map(process_csv_file, args)

                # Filter out empty results
                time_ranges.extend([result for result in results if result])

    except Exception as e:
        logger.error(f"Error during parallel processing: {e}")

    # Convert to DataFrame
    time_ranges_df = pd.DataFrame(time_ranges)
    return time_ranges_df

# Function to get relevant CSV files based on the time range
def get_relevant_csvs(time_ranges_df, new_min_timestamp, new_max_timestamp):
    relevant_csvs = time_ranges_df[
        (time_ranges_df['min_timestamp'] <= new_max_timestamp) &
        (time_ranges_df['max_timestamp'] >= new_min_timestamp)
    ]
    return relevant_csvs

# Function to read relevant CSVs into a single DataFrame
def read_relevant_csvs(relevant_csvs_df):
    df_list = []

    for _, row in relevant_csvs_df.iterrows():
        try:
            df = pd.read_csv(row['file_path'],low_memory=False)
            df_list.append(df)
            print(f"Reading: {row['file_path']}")
        except Exception as e:
            print(f"Failed to read {row['file_path']}: {e}")

    # Concatenate all DataFrames into one
    if df_list:
        combined_df = pd.concat(df_list, ignore_index=True)
    else:
        combined_df = pd.DataFrame()

    return combined_df

def prepare_unlabeled_csv_flowid(csv_address):
    df1=pd.read_csv(csv_address,low_memory=False)
    df1['flowid']=df1['src_ip'].astype(str)+'-'+df1['dst_ip'].astype(str)+'-'+df1['src_port'].astype(str)+'-'+df1['dst_port'].astype(str)
    return df1

def prepare_labeled_csv_flowid(df2):
    #df2=pd.read_csv(csv_address,low_memory=False)
    df2.columns=df2.columns.str.replace(' ','')
    df2.columns=df2.columns.str.lower()
    # Automatically extract column names for source IP, destination IP, source port, and destination port
    src_ip = df2.columns[df2.columns.str.contains(r'(src|source).*ip', case=False, regex=True)].tolist()[0]
    dst_ip = df2.columns[df2.columns.str.contains(r'(dst|destination).*ip', case=False, regex=True)].tolist()[0]
    src_port = df2.columns[df2.columns.str.contains(r'(src|source).*port', case=False, regex=True)].tolist()[0]
    dst_port = df2.columns[df2.columns.str.contains(r'(dst|destination).*port', case=False, regex=True)].tolist()[0]
    df2['flowid']=df2[src_ip].astype(str)+'-'+df2[dst_ip].astype(str)+'-'+df2[src_port].astype(str)+'-'+df2[dst_port].astype(str)
    return df2

def filter_matching_flowid(df1, df2, column_name='flowid'):
    if column_name not in df1.columns or column_name not in df2.columns:
        raise ValueError(f"Column '{column_name}' not found in both DataFrames")
    
    common_flowids = pd.merge(df1[[column_name]], df2[[column_name]], on=column_name, how='inner')[column_name]
    
    df1_filtered = df1[df1[column_name].isin(common_flowids)].copy()
    df2_filtered = df2[df2[column_name].isin(common_flowids)].copy()
    
    return df1_filtered, df2_filtered

# Function to add labels to df1 based on time range in df2
def label_based_on_time(df1_filtered, df2_filtered,label_col='label'):
    # Initialize a new 'label' column in df1_filtered with default values (e.g., 'No Match')
    df1_filtered['label'] = 'No Match'

    # Iterate over each row in df2_filtered and apply the time range filtering
    for _, row in df2_filtered.iterrows():
        # Find rows in df1_filtered where 'first_seen_ms' is in the time range of df2's start and end timestamps
        condition = (
            (df1_filtered['bidirectional_first_seen_ms'] >= row['start_timestamp_ms']) & 
            (df1_filtered['bidirectional_first_seen_ms'] <= row['end_timestamp_ms'])
        )
        
        # Assign the 'label' from df2 to the matching rows in df1
        df1_filtered.loc[condition, 'label'] = row[label_col]
    
    return df1_filtered


def datetime_to_timestamp(df, timestamp_column, timezone, flow_duration_column,unit='ms'):
    if timezone!='None':
        # Convert the column to datetime and localize to the provided timezone
        df['localized_timestamp'] = pd.to_datetime(df[timestamp_column])
        
        # Apply the timezone to the datetime
        zone_time = pytz.timezone(timezone)
        df['localized_timestamp'] = df['localized_timestamp'].apply(lambda dt: zone_time.localize(dt))
        
        # Calculate the start timestamp in milliseconds
        df['start_timestamp_ms'] = df['localized_timestamp'].apply(lambda dt: dt.timestamp() * 1000)
        
        # Convert flow duration from microseconds to milliseconds
        df['flow_duration_ms'] = df[flow_duration_column] / 1000
    
        # Calculate the end timestamp by adding flow duration to the start timestamp
        df['end_timestamp_ms'] = df['start_timestamp_ms'] + df['flow_duration_ms']
    else:
        if unit=='sec':
            df['start_timestamp_ms'] = df[timestamp_column]*1000
            df['end_timestamp_ms'] = df['start_timestamp_ms'] + df[flow_duration_column]*1000
        elif unit=='ms':
            df['start_timestamp_ms'] = df[timestamp_column]
            df['end_timestamp_ms'] = df['start_timestamp_ms'] + df[flow_duration_column]
    
    return df


def process_csv(csv_file, input_folder, output_path, time_ranges_df, timezone,
                unit='ms',timestamp_col='timestamp',flowduration_col='flowduration',label_col='label'):
    try:
        # Prepare the CSV file path
        csv_file_path = os.path.join(input_folder, csv_file)

        # Step 1: Prepare unlabeled CSV flowid using the provided function
        df1 = prepare_unlabeled_csv_flowid(csv_file_path)
        relevant_csvs_df = get_relevant_csvs(time_ranges_df, min(df1['bidirectional_first_seen_ms']), max(df1['bidirectional_first_seen_ms']))

        # Step 3: Read relevant CSV files into a single DataFrame
        df2 = read_relevant_csvs(relevant_csvs_df)
        df2 = prepare_labeled_csv_flowid(df2)

        # Step 2: Filter based on flowid matching between df1 and df2
        df1_filtered, df2_filtered = filter_matching_flowid(df1, df2)

        # Step 3: Apply datetime transformation to df2_filtered
        df2_filtered = datetime_to_timestamp(df2_filtered, timestamp_col, timezone, flowduration_col,unit)

        # Step 4: Label df1 based on the time range in df2
        df1_with_labels = label_based_on_time(df1_filtered, df2_filtered,label_col)

        # Step 5: Remove 'Unnamed' columns if they exist
        df1_with_labels = df1_with_labels.loc[:, ~df1_with_labels.columns.str.contains('^Unnamed')]

        # Step 6: Write the labeled DataFrame to the 'labeled_csv' folder
        output_csv_path = os.path.join(output_path, csv_file)
        df1_with_labels.to_csv(output_csv_path, index=False)

        # Return label distribution for reporting
        return csv_file, df1_with_labels['label'].value_counts()

    except Exception as e:
        return csv_file, f"Failed to process {csv_file}. Error: {e}"

def label_csvs(input_folder, time_ranges_df, output_folder="labeled_csv", timezone='Canada/Atlantic', num_workers=2,
               unit='ms',timestamp_col='timestamp',flowduration_col='flowduration',label_col='label'):
    # Create the 'labeled_csv' folder if it doesn't exist
    output_path = os.path.join(input_folder, output_folder)
    os.makedirs(output_path, exist_ok=True)

    # Get a list of all CSV files in the input folder
    csv_files = [f for f in os.listdir(input_folder) if f.endswith(".csv")]

    # Process CSVs in parallel using ProcessPoolExecutor
    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        futures = []
        for csv_file in csv_files:
            futures.append(executor.submit(process_csv, csv_file, input_folder, output_path, time_ranges_df, timezone,unit,timestamp_col,flowduration_col,label_col))

        # Process the results as they complete
        for future in tqdm(as_completed(futures), total=len(futures), desc="Processing CSVs"):
            try:
                result = future.result()
                if isinstance(result[1], pd.Series):
                    print(f"Finished processing {result[0]}.")
                    print("Label distribution:")
                    print(result[1])
                else:
                    print(result[1])
            except Exception as e:
                print(f"Error in future: {e}")




