## File Descriptions

### `Undersampled UM-NIDS.ipynb`
This notebook shows how different machine learning models can be trained and evaluated on the standardized flow features provided in the undersampled version of UM-NIDS dataset. 
### `Multimodal NIDS Comparison.ipynb`
This notebook compares the performance of NIDS models trained using multimodal features (flow + payload) against models trained using flow features only. It includes an evaluation of the models' robustness and accuracy, showing how multimodal data can improve NIDS performance.

### `Payload cross validation` (folder)
This folder contains script for cross-validating payload-based NIDS using TF-IDF (Term Frequency-Inverse Document Frequency) representations of payload data. It demonstrates the resilience of payload-based NIDS against payload-specific attacks and compares their performance on various datasets against flow-only models.

### `CIC-IDS 17` (folder)
This folder contains notebooks for processing the CIC-IDS 2017 dataset. The notebooks include:
- PCAP file processing and flow feature extraction
- Model training and evaluation with and without contextual features
- Handling timestamp issues, timezones, and dataset-specific configurations 

### `CIC-IDS DDoS 19` (folder)
This folder contains notebooks focused on processing the CIC-IDS DDoS 2019 dataset. It includes:
- PCAP processing for Distributed Denial of Service (DDoS) attack detection
- Feature extraction and timestamp alignment
- Training and evaluating models using flow features with/without contextual data

### `CIC-IoT 23` (folder)
In this folder, the CIC-IoT 2023 dataset is labeled based on MAC addresses (unlike the other datasets, which use pre-labeled CSV files). The notebooks demonstrate:
- Custom labeling based on MAC addresses
- Handling of timestamps and timezones (during labeling)
- Training models with both flow and payload features for improved performance

### `UNSW` (folder)
This folder contains processing scripts and evaluation notebooks for the UNSW dataset. The notebooks focus on:
- PCAP processing and flow feature extraction
- Handling of timestamps and timezones (during labeling)
- Handling specific dataset structures and evaluating models with/without contextual features

---
