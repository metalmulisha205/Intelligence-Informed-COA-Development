# the purpose of this script is to generate the STIX bundle for the Activity-Attack Graph
# usage: ./gen_aag.py [abstract/specific (a/s)] [min confidence] [min support] [intel seed as space seperated list] [export file name]
import sys







# taken from mitre stix - https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md#access-the-most-recent-version-from-github-via-requests
def technique_mitigated_by_mitigations(thesrc):
    """return technique_id => {mitigation, relationship} for each mitigation of the technique."""
    return get_related(thesrc, "course-of-action", "mitigates", "attack-pattern", reverse=True)

def get_mitigations_from_technique(thesrc, stix_id):
    # returns list of mitigation objects and relationships linked to attack pattern object
    mitigations = technique_mitigated_by_mitigations(src)
    if (stix_id in mitigations.keys()):
        mitigations = mitigations[stix_id]
    else:
        mitigations = []
    return mitigations

# each rule has a confidence, lift, support, lhs, rhs, conviction, rule power factor (RPF), 

# takes an APTGroup and generates hypothesized relationships and attack pattern objects
# returns a tuple of: (displayInfo, attackPatterns, relationships, groupings, mitigationObjects)
def CreateRelationships(seeds, aprioriLists, minsupp, minconf):
    displayInfo = [] #stores the TTP and tactic for easy logging
    seen = [] #stores TTPs that have been seen by the algorithm
    attackPatterns = [] #stores generated attack pattern objects
    relationships = {} # stores generated relationship objects
    groupings = {} # stores generated grouping objects
    
    mitigationRelationships = {} # {stix id, object}
    mitigationObjects = {} # {stix id, [COA object, count]} #stores all mitigation objects
    
    # perform association rule mining
    rules = AprioriMining(aprioriLists, minsupp, minconf) 
    
    #add seeds to activity-attack-graph as nodes
    for seed in seeds:
        # get the stix object for the TTP
        ttp = src.query([ Filter("external_references.external_id", "=", seed) ])[0]
        
        # create and add objects to lists, context is used to identify seeds from hypothesized events
        groupings[seed] = (Grouping(object_refs=[ttp.id], context = "Seed Event"))
        attackPatterns.append(src.query([ Filter("external_references.external_id", "=", seed) ])[0])
    
    seedTotals = ["'"+x+"'" for x in seeds]
    # use a queue to iterate through and create a tree of TTPs
    while len(seeds) > 0:
        for rule in rules:
            # check to see if the left hand side of a rule is satisfied 
            if "'"+seeds[0]+"'" in rule.lhs and set(rule.lhs).issubset(seedTotals):
                #if the lhs is satisfied, then loop through each TTP in the rhs 
                for ttpName in rule.rhs:
                    # if this TTP hasn't been visited already then create STIX objects
                    if ttpName not in seen:
                        ttp = src.query([ Filter("external_references.external_id", "=", ttpName[1:-1]) ])[0]
                        
                        # track rule tactics for logging to displayInfo
                        tactics = []
                        for i in ttp['kill_chain_phases']:
                            tactics.append(i['phase_name'])
                        
                        mitigations = get_mitigations_from_technique(src, ttp.id)
                        for m in mitigations:
                            mitigation = m["object"]
                            relationship = m["relationship"]
                            mitigationRelationships[relationship.id] = relationship
                            if mitigation.id in mitigationObjects.keys():
                                mitigationObjects[mitigation.id][1] += 1
                            else:
                                mitigationObjects[mitigation.id] = [mitigation, 1]
                        
                        # create a new grouping object with the rule name. 
                        # I am using ttpName[1:-1] here because TTPs have quotes around them for some reason 
                        # so I want to get rid of the quotes
                        # later I will fix this issue so that ttpName[1:-1] is not neccessary
                        groupings[ttpName[1:-1]] = (Grouping(object_refs=[ttp.id]+[mitigation["object"].id for mitigation in mitigations], context = "Hypothesized Event"))
                        #groupings[ttpName[1:-1]] = (Grouping(object_refs=[ttp.id, MITIGATION OBJECT ID], context = "Hypothesized Event"))
                        

                        
                        displayInfo.append([ttp['name'], ttpName[1:-1], tactics])
                        attackPatterns.append(ttp)
                        seedTotals.append(ttpName)
                        seen.append(ttpName)
                        seeds.append(ttp['external_references'][0]['external_id'])

                    # if the relationship already exists between two objects then we take the one with higher confidence
                    # make sure the exact relationship does not alraedy exist
                    if not (groupings[seeds[0]]['id'], groupings[ttpName[1:-1]]['id']) in relationships:
                        # if the opposite relationship exists then choose the one with the highest confidence to add
                        # we do this because if we do not then on the graph there will be two arrows going opposite directions to connect the same 2 TTPs
                        # this causes clutter and makes the confidence values unreadable since they will be layered on top of each other
                        if (groupings[ttpName[1:-1]]['id'], groupings[seeds[0]]['id']) in relationships:
                            # if existing relationship has higher confidence, move on
                            if float(relationships[(groupings[ttpName[1:-1]]['id'], groupings[seeds[0]]['id'])]['relationship_type']) > rule.confidence:
                                continue # move to next iteration of for loop, so code after this statement won't execute
                            # if existing relationship has lower confidence, delete it and let the new relationship take it's place
                            else:
                                del relationships[(groupings[ttpName[1:-1]]['id'], groupings[seeds[0]]['id'])]
                        relationships[(groupings[seeds[0]]['id'], groupings[ttpName[1:-1]]['id'])] = Relationship(groupings[seeds[0]]['id'], str(round(rule.confidence, 3)), groupings[ttpName[1:-1]]['id'])
        
        # pop to progress the queue
        seeds.pop(0)

    return (displayInfo, attackPatterns, relationships, groupings, mitigationObjects, mitigationRelationships)




if __name__ == "__main__":
    argv = sys.argv
    if (len(argv) != 6):
        print("./gen_aag.py [abstract/specific (a/s)] [min confidence] [min support] [intel seed] [export file name]")
        print("Where intel seed is a space sperated list of observed TTPs")
    else:
        from stix2.v21 import (Relationship, Bundle, Grouping)
        from stix2 import Filter
        print("loading helper functions, this could take several minutes")
        from src.helpers import *
        
        
        src = get_data_from_branch("enterprise-attack")
        
        # Settings Values - for apriori algorithm
        confidenceLevel = float(argv[2])
        supportLevel = float(argv[3])
        abstract = argv[1].lower() == 'a' or argv[1].lower() == 'abstract'

        print("loading apriori lists")
        aprioriList = GenerateAprioriLists()
        
        if (abstract):
            aprioriList = AbstractTTPs(aprioriList)

        #intelSeed = ["T1566", "T1204"]
        print("generating AAG")
        intelSeed = argv[4].split(" ")
        displayInfo, attackPatterns, relationships, groupings, mitigationObjects, mitigationRelationships = CreateRelationships(intelSeed, aprioriList, supportLevel, confidenceLevel)

        # bundle up stix objects
        bundle = Bundle(attackPatterns+list(groupings.values())+list(relationships.values()), allow_custom=True)

        # export stix objects for visualization here: https://github.com/yukh1402/cti-stix-diamond-activity-attack-graph
        ExportBundle(bundle, "bundles/" + argv[5])
        
        print("AAG Generation complete. See the bundles folder to get your exported STIX bundle.")
            