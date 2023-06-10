# a compilation of simple helper functions used by the AAG Generation

from pyattck import Attck
import pandas as pd 
from stix2 import MemoryStore, Filter
import requests
import re
import numpy as np
from efficient_apriori import apriori

def NameToCode(gName):
    # create an instance of the Attck class
    attck = Attck()

    # get all APT groups in the framework
    apt_groups = attck.enterprise.actors

    # create a dictionary mapping APT group names to G codes
    group_to_gcode = {}
    for group in apt_groups:
        if group.name == gName:
            gcode = group.id
            return gcode
    return ""

# generate lists of ttps for the apriori rule mining
def GenerateAprioriLists():
    # some data comes from this dataset with TTPs
    df = pd.read_csv("datasets/TTP_Data.csv") # sample dataset of attacks

    # to use the apriori we need to generate a list of lists
    aprList = []
    for row in df.values:
        if (type(row[1]) == type('')):  
            aprList.append((row[1].strip('][').split(', ')))
    return aprList

# convert sub-techniques to abstract techniques 
def AbstractTTPs(ttpList):
    # take sub-techniques and remove the .### to abstract them to parent techniques 
    for i in range(0,len(ttpList)):
        ttpList[i] = [re.sub(r'\.[0-9]+', '', ttp) for ttp in ttpList[i]]
    return ttpList 

# takes a list of lists and returns a list of rules sorted by size 
def AprioriMining(aprList, supportLevel, confidenceLevel):
    # perform apriori rule association mining
    itemsets, rules = apriori(aprList, min_support=supportLevel, min_confidence=confidenceLevel)
    
    # sort by size to get the 1:1 mappings first and so on. 
    ruleNums = np.array([len(rule.lhs+rule.rhs) for rule in rules])
    rules = np.array(rules)
    inds = ruleNums.argsort()[::]
    rules = rules[inds]
    
    # maximum rule size of 4 to limit number of rules, any rules with size > 4 are redundant anyways
    rules = [x for x in filter(lambda rule: len(rule.lhs+rule.rhs) <= 4, rules)]
    return rules

# downloads latest MITRE framework from the branch
def get_data_from_branch(domain):
    """get the ATT&CK STIX data from MITRE/CTI. Domain should be 'enterprise-attack', 'mobile-attack' or 'ics-attack'. Branch should typically be master."""
    stix_json = requests.get(f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/{domain}/{domain}.json").json()
    return MemoryStore(stix_data=stix_json["objects"])

def ExportBundle(bundle, filename):
    with open(filename, "w") as f:
        f.write(bundle.serialize())
        f.close()

# taken from mitre stix - https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md#access-the-most-recent-version-from-github-via-requests
def get_related(thesrc, src_type, rel_type, target_type, reverse=False):
    """build relationship mappings
       params:
         thesrc: MemoryStore to build relationship lookups for
         src_type: source type for the relationships, e.g "attack-pattern"
         rel_type: relationship type for the relationships, e.g "uses"
         target_type: target type for the relationship, e.g "intrusion-set"
         reverse: build reverse mapping of target to source
    """

    relationships = thesrc.query([
        Filter('type', '=', 'relationship'),
        Filter('relationship_type', '=', rel_type),
        Filter('revoked', '=', False),
    ])

    # See section below on "Removing revoked and deprecated objects"
    relationships = remove_revoked_deprecated(relationships)

    # stix_id => [ { relationship, related_object_id } for each related object ]
    id_to_related = {}

    # build the dict
    for relationship in relationships:
        if src_type in relationship.source_ref and target_type in relationship.target_ref:
            if (relationship.source_ref in id_to_related and not reverse) or (relationship.target_ref in id_to_related and reverse):
                # append to existing entry
                if not reverse:
                    id_to_related[relationship.source_ref].append({
                        "relationship": relationship,
                        "id": relationship.target_ref
                    })
                else:
                    id_to_related[relationship.target_ref].append({
                        "relationship": relationship,
                        "id": relationship.source_ref
                    })
            else:
                # create a new entry
                if not reverse:
                    id_to_related[relationship.source_ref] = [{
                        "relationship": relationship,
                        "id": relationship.target_ref
                    }]
                else:
                    id_to_related[relationship.target_ref] = [{
                        "relationship": relationship,
                        "id": relationship.source_ref
                    }]
    # all objects of relevant type
    if not reverse:
        targets = thesrc.query([
            Filter('type', '=', target_type),
            Filter('revoked', '=', False)
        ])
    else:
        targets = thesrc.query([
            Filter('type', '=', src_type),
            Filter('revoked', '=', False)
        ])

    # build lookup of stixID to stix object
    id_to_target = {}
    for target in targets:
        id_to_target[target.id] = target

    # build final output mappings
    output = {}
    for stix_id in id_to_related:
        value = []
        for related in id_to_related[stix_id]:
            if not related["id"] in id_to_target:
                continue  # targeting a revoked object
            value.append({
                "object": id_to_target[related["id"]],
                "relationship": related["relationship"]
            })
        output[stix_id] = value
    return output

def remove_revoked_deprecated(stix_objects):
    """Remove any revoked or deprecated objects from queries made to the data source"""
    # Note we use .get() because the property may not be present in the JSON data. The default is False
    # if the property is not set.
    return list(
        filter(
            lambda x: x.get("x_mitre_deprecated", False) is False and x.get("revoked", False) is False,
            stix_objects
        )
    )

