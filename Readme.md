# <img src="/logo.png" width="140" valign="middle"  />&nbsp; Unified, Multimodal NIDS Dataset Tool

<meta name="google-site-verification" content="5WK343ADbdgrsx0UqyrJwGNjU5xKzLWjmNP7f502qWo" />

[![DOI](https://zenodo.org/badge/524051176.svg)](https://zenodo.org/badge/latestdoi/524051176)

<p align="justify"> The Unified, Multimodal NIDS Dataset tool is designed to address the issue of inconsistent feature sets across publicly available network intrusion detection system (NIDS) datasets. Many existing datasets vary significantly in their features, have inconsistent labeling, and often exclude crucial payload and contextual information, limiting the effectiveness of machine learning-based models. </p>

<p align="justify"> Our tool resolves these challenges by providing a standardized method for converting any raw PCAP dataset into a uniform format with consistent features, ensuring compatibility and enhancing the potential for cross-dataset analysis. It extracts key flow-level features such as source and destination IPs, ports, protocols, packet counts, and flow duration, while also integrating detailed payload data, which is often excluded in traditional datasets. This is particularly important for identifying attacks that rely on specific payload characteristics, such as SQL injection or malware. Additionally, the tool generates contextual features based on a sliding time window, capturing historical and temporal patterns in network traffic. </p>

<p align="justify"> These contextual features are crucial for detecting advanced persistent threats (APT), where the timing and sequence of packets play a significant role. A comprehensive description of all features developed by the dataset, including flow, payload, and contextual features, is available in the `features_meta_data.pdf` document, offering users detailed insights into the structure and content of the unified dataset. </p>

## Dataset Coverage
<p align="justify"> The Unified Multimodal NIDS Dataset includes processed data from four publicly available, well-established network intrusion detection datasets: CIC-IDS 2017, CIC-IoT 2023, UNSW-NB15, and a DDoS-specific dataset. These datasets have been standardized to ensure consistency in feature sets, including flow, payload, and contextual data. Additionally, the tool supports the extension of the dataset by allowing users to process and add new datasets, converting raw PCAP files into the same unified format. This flexibility ensures that the dataset can be expanded further to accommodate evolving research needs. </p>

You can access the dataset [here](#).

## Tool Usage Guide

#### Step 1: Processing PCAP Files
The process of generating the Unified Multimodal (UM) dataset begins with processing raw PCAP files. The first step involves using the tool to convert PCAP files into CSV format containing payload content, statistical flow features, and contextual window-based features. This can be achieved with the following command:

```python
from pcap_process.flow_payload import *
pcap_process(dataset_folder=folder_name, window_size, vulnerable_ports_list, http_ports_list, idle_timeout, active_timeout, flowlimit)

```

Key parameters such as the rolling window size, the list of ports to monitor, and flow termination criteria (based on active timeout, idle timeout, or packet limit) can be customized to suit your specific needs. This allows for flexible dataset generation based on the features most relevant to your analysis.

The tool extracts flow-level features, payload content, and contextual features based on a sliding time window, providing a detailed dataset ready for further processing and labeling in the next steps.

#### Step 2: Preparing Pre-labeled CSVs
In the second step, the tool requires pre-labeled CSVs. These CSVs must include:
- Timestamp Column: This can be in Unix format or a timestamp in any timezone, but the timezone must be known to the user.
- Flow Duration Column: A column indicating the duration of each flow.
- Source/Destination IP and Ports: Columns containing source and destination IPs and ports for labeling purposes.
To label the processed CSVs from Step 1, use the following commands:

```python
from label.parallel_label import *
# Extract metadata from pre-labeled CSVs
meta_data = extract_time_ranges_from_csvs(folders, timestamp_column='timestamp', timezone='None', batch_size=5)
```

#### Step 3: Labeling Processed CSVs
Finally, use the metadata to label the processed CSVs:
```python
label_csvs(input_folder, meta_data, output_folder="labeled_csv", timezone='Canada/Atlantic', num_workers=2, unit='ms', timestamp_col='timestamp', flowduration_col='flowduration', label_col='label')
```

- input_folder: Directory containing the processed CSV files.
- meta_data: Extracted metadata for matching and labeling.
- output_folder: The folder where labeled CSVs will be saved (will be created in the input folder).
- timezone: Specify the timezone.
- num_workers: Number of parallel workers for processing.
This workflow ensures smooth processing and labeling of PCAP files into a unified dataset format, ready for machine learning analysis.

## Example Usage

This repository contains example Jupyter notebook (.ipynb) files demonstrating the processing of all four datasets included in the UM-NIDS dataset. Additionally, it includes the performance evaluation of a Random Forest-based machine learning classifier.

You will also find examples of payload-based NIDS processing in the file [payload_based_Cross_validation.ipynb](https://github.com/SyedWaliAbbas/Unified-Network-Intrusion-Dataset/blob/main/Dataset%20Examples/Payload%20cross%20validation/payload_cross_validation_example.ipynb), where we cross-validate payload-specific attacks.

Moreover, we have trained and tested various classifiers on the undersampled version of the UM-NIDS dataset in [undersampled.ipynb](https://github.com/SyedWaliAbbas/Unified-Network-Intrusion-Dataset/blob/main/Dataset%20Examples/Undersampled%20UM-NIDS.ipynb), showcasing the tool’s flexibility and ease of use in different machine learning scenarios.

