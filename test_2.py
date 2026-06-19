import json
import pandas as pd
attack_docs = {}
attack_df = pd.read_excel("attack_dataset.xlsx")
for _, row in attack_df.iterrows():
    attack_docs[row["Technique_ID"]] = (
        row["Technique_ID"],row["Technique_Description"],row["Tactic_Name"],row["Tactic_Description"],row["Technique_Name"]
    )
with open("training-data.json", "r", encoding="utf-8") as f:
    data = json.load(f)
pairs = []
for item in data["sentences"]:
    query = item["text"]
    for mapping in item["mappings"]:
        attack_id = mapping["attack_id"]
        if attack_id in attack_docs:
            pairs.append({
                "query": query,
                "technique_id": attack_docs[attack_id][0],
                "technique_name":attack_docs[attack_id][4],
                "technique_description":attack_docs[attack_id][1],
                "tactic_name":attack_docs[attack_id][2],
                "tactic_description":attack_docs[attack_id][3]
            })
with open("train_pairs.json", "w", encoding="utf-8") as f:
    json.dump(pairs, f, indent=2)