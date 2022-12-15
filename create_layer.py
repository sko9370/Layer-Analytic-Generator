# pip install mitreattack-python loguru stix2 tqdm

from mitreattack.navlayers import UsageLayerGenerator
import mitreattack.attackToExcel.attackToExcel as attackToExcel
import mitreattack.attackToExcel.stixToDf as stixToDf
from mitreattack.navlayers.core import Layer
from mitreattack.navlayers.core.objlink import LinkDiv
import pandas as pd

# add in desired Group or Software IDs here
ids = ['G0027', 'G0007', 'G0016']

# Get all STIX

# download and parse ATT&CK STIX data
attackdata = attackToExcel.get_stix_data("enterprise-attack")
# get list of Pandas DataFrames for techniques, associated relationships, and citations
techniques_data = stixToDf.techniquesToDf(attackdata, "enterprise-attack")
techniques_df = techniques_data["techniques"]
#print(techniques_df[techniques_df["ID"].str.contains("T1102")]["name"])
procedure_df = techniques_data['procedure examples']

# Get all Procedure Examples

def cite_link(citations):
    links = []
    for citation in citations:
        links.append((citation[11:-1], citations_df[citations_df['reference'].str.contains(citation[11:-1])].iloc[0]['url']))
    return links

procedure_dfs = []
for id in ids:
    procedure_dfs.append(procedure_df[procedure_df['source ID'] == id][['source ID', 'target ID', 'mapping description']].copy())
df = pd.concat(procedure_dfs)
df['citation'] = df['mapping description'].str.extractall(r'[^(]*(?P<citation>\(Citation: [^)]+\))').groupby(level=0).agg(lambda x: list(x))['citation']
df['description'] = df['mapping description'].str.replace(r'\([^\)]*?\)|\[|\]', '', regex=True)
df = df[['source ID', 'target ID', 'description', 'citation']]

citations_df = techniques_data['citations'][['reference', 'url']]

df['links'] = df['citation'].apply(cite_link)
df = df[['source ID', 'target ID', 'description', 'links']]

# Create Layer

layer_dict = {
    "name": "layer example",
    "versions" : {
        "attack": "11",
        "layer" : "4.3",
        "navigator": "4.7.1"
    },
    "domain": "enterprise-attack",
    "techniques": list(),
    "sorting": 3,
    "layout": {
		"layout": "flat",
		"aggregateFunction": "sum",
		"showID": False,
		"showName": True,
		"showAggregateScores": True,
		"countUnscored": False
	},
    "gradient": {
		"colors": [
			"#8ec843ff",
			"#ffe766ff",
			"#ff6666ff"
		],
		"minValue": 1,
		"maxValue": 100
	},
	"legendItems": [],
	"metadata": [],
	"links": [],
	"showTacticRowBackground": False,
	"tacticRowBackground": "#dddddd",
	"selectTechniquesAcrossTactics": True,
	"selectSubtechniquesWithParent": False
}

techniques_dict = {}

def df_to_layer(row, techniques_dict, techniques_df):
    # technique exists
    if row['target ID'] in techniques_dict:
        technique = dict()
        technique['techniqueID'] = row['target ID']
        all_tactics = techniques_df[techniques_df['ID']==row['target ID']].iloc[0]['tactics']
        technique['tactic'] = techniques_dict[row['target ID']]['tactic']
        technique['metadata'] = techniques_dict[row['target ID']]['metadata']
        technique['metadata'].append(
            {'name': row['source ID'], 'value': row['description']}
        )
        technique['links'] = techniques_dict[row['target ID']]['links']

        technique['links'].append({'divider': True})

        technique['score'] = techniques_dict[row['target ID']]['score'] + 1

        for label, link in row['links']:
            link_dict = dict()
            link_dict['label'] = label
            link_dict['url'] = link
            technique['links'].append(link_dict.copy())
        techniques_dict[row['target ID']] = technique.copy()
    # technique does not exist
    else:
        technique = dict()
        technique['techniqueID'] = row['target ID']
        
        tactics_priority = ['Command and Control', 'Exfiltration', 'Execution', 'Initial Access',
                            'Discovery', 'Lateral Movement', 'Defense Evasion', 'Persistence',
                            'Privilege Escalation', 'Credential Access', 'Collection', 'Impact',
                            'Resource Development', 'Reconnaissance']
        all_tactics = techniques_df[techniques_df['ID']==row['target ID']].iloc[0]['tactics'].split(', ')
        for priority in tactics_priority:
            if priority in all_tactics:
                # 2 word tactics like "resource-development"
                technique['tactic'] = '-'.join(priority.split()).lower()
                break
        technique['metadata'] = list()
        technique['metadata'].append({'name': row['source ID'], 'value': row['description']})
        technique['score'] = 1
        technique['links'] = list()
        for label, link in row['links']:
            link_dict = dict()
            link_dict['label'] = label
            link_dict['url'] = link
            technique['links'].append(link_dict.copy())
        techniques_dict[row['target ID']] = technique.copy()

df.apply(df_to_layer, axis=1, techniques_dict=techniques_dict, techniques_df=techniques_df)
layer_dict['techniques'] = list(techniques_dict.values())

maxValue = 1
for technique in layer_dict['techniques']:
    if technique['score'] > maxValue:
        maxValue = technique['score']

# set layer background color based on high and low scores
layer_dict['gradient']['maxValue'] = maxValue

output_layer = Layer(layer_dict)
output_layer.to_file('layer.json')