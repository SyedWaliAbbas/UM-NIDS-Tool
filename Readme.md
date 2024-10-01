# <img src="/logo.png" width="140" valign="middle"  />&nbsp; Unified, Multimodal NIDS Dataset Tool

<meta name="google-site-verification" content="5WK343ADbdgrsx0UqyrJwGNjU5xKzLWjmNP7f502qWo" />

[![DOI](https://zenodo.org/badge/524051176.svg)](https://zenodo.org/badge/latestdoi/524051176)

<p align="justify"> The Unified, Multimodal NIDS Dataset tool is designed to address the issue of inconsistent feature sets across publicly available network intrusion detection system (NIDS) datasets. Many existing datasets vary significantly in their features, have inconsistent labeling, and often exclude crucial payload and contextual information, limiting the effectiveness of machine learning-based models. </p>

<p align="justify"> Our tool resolves these challenges by providing a standardized method for converting any raw PCAP dataset into a uniform format with consistent features, ensuring compatibility and enhancing the potential for cross-dataset analysis. It extracts key flow-level features such as source and destination IPs, ports, protocols, packet counts, and flow duration, while also integrating detailed payload data, which is often excluded in traditional datasets. This is particularly important for identifying attacks that rely on specific payload characteristics, such as SQL injection or malware. Additionally, the tool generates contextual features based on a sliding time window, capturing historical and temporal patterns in network traffic. </p>

<p align="justify"> These contextual features are crucial for detecting advanced persistent threats (APT), where the timing and sequence of packets play a significant role. A comprehensive description of all features developed by the dataset, including flow, payload, and contextual features, is available in the `features_meta_data.pdf` document, offering users detailed insights into the structure and content of the unified dataset. </p>

## Dataset Coverage
<p align="justify"> The Unified Multimodal NIDS Dataset includes processed data from four publicly available, well-established network intrusion detection datasets: CIC-IDS 2017, CIC-IoT 2023, UNSW-NB15, and a DDoS-specific dataset. These datasets have been standardized to ensure consistency in feature sets, including flow, payload, and contextual data. Additionally, the tool supports the extension of the dataset by allowing users to process and add new datasets, converting raw PCAP files into the same unified format. This flexibility ensures that the dataset can be expanded further to accommodate evolving research needs. </p>

You can access the dataset [here](#).

