import pandas as pd
attack_docs = {}
attack_df = pd.read_excel("attack_dataset.xlsx")
for _, row in attack_df.iterrows():
    attack_docs[row["Technique_ID"]] = (
        row["Technique_Name"] + ". " + row["Technique_Description"],row["Tactic_ID"]+". " + row["Tactic_Name"]
    )
