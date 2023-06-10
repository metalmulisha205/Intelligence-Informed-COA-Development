# Activity-Attack Graphs for Intelligence-Informed Threat COA Development
## Purpose
This github repository contains code used to perform research in the field of cyber threat COA development. This research was published in CCWC 2023 (https://ieee-ccwc.org/). The paper can be found IEEE: https://ieeexplore.ieee.org/document/10099277
## Extension
This research has been extended to include theat profiling. To view the extended work please see this repository here:
https://github.com/KelsieEdie/Extending-Threat-Playbooks-for-APT-Attribution
## Abstract
A threat course of action (COA) describes the likely
tactics, techniques, and procedures (TTPs) an adversary may
deploy across the cyber kill-chain. Threat COA development
and analysis informs hunt teams, incident responders, and threat
emulation efforts on likely activities the adversary will conduct
during an attack. In this paper, we propose a novel approach
to generate and evaluate threat COAs through association rule
mining. We identify frequent TTP itemsets to create a set of activ-
ity groups that describe associations between TTPs. We overlay
activity groups to create a directed and edge-weighted activity-
attack graph. The graphs hypothesize various adversary avenues
of attack, and the weighted edges inform the analyst’s trust of a
hypothesized TTP in the COA. Our research identifies meaningful
associations between TTPs and provides an analytical approach
to generating threat COAs. Further, our implementation uses the
STIX framework for extensibility and usability in a variety of
threat intelligence environments.
## Contents
* gen_aag.py - python file to generate an AAG on the command line given a seed as an argument.
* TTP_AAG.ipynb - contains the python notebook used to create the activity groups and generate the stix bundle of the activity attack graph.
* TTP_Data.csv - final dataset compiled from both Categorized_Adversary_TTPs.csv and pyattck. 
* Categorized_Adversary_TTPs.csv - This dataset is compiled from various cyber attacks. It contains metadata on the attacks and includes a list of ATT&CK T-codes: https://github.com/tropChaud/Categorized-Adversary-TTPs
* AbstractRules.csv - a CSV file of the abstract rules extracted from the dataset after replacing all sub-techniques with their parent technique. 
* SpecificRules - a CSV file of the specific rules extracted from the dataset. These rules have a combination of both techniques and sub-techniques. 
## Bibtex Citation
```
@inproceedings{mckee_edie_activity_2023,
  title={Activity-Attack Graphs for Intelligence-Informed Threat COA Development},
  author={Mckee, Cole and Edie, Kelsie and Duby, Adam},
  booktitle={2023 IEEE 13th Annual Computing and Communication Workshop and Conference (CCWC)},
  year={2023},
  organization={IEEE}
}
```
