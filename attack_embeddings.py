
import pandas as pd
from sentence_transformers import SentenceTransformer
import pickle
import numpy as np
model = SentenceTransformer(
    "./e5_attack_mapper"
)
df = pd.read_excel("attack_dataset.xlsx")

attack_docs = []
attack_ids = []
attack_metadata=[]

for _, row in df.iterrows():

    passage = f"""
Technique Name:
{row['Technique_Name']}

Tactic:
{row['Tactic_Name']}

Technique Description:
{row['Technique_Description']}

""".strip()
    attack_metadata.append({
        "attack_id": row["Technique_ID"],
        "name": row["Technique_Name"],
        "tactic": row["Tactic_Name"],
        "tactic_id":row["Tactic_ID"]
    })
    attack_docs.append(passage)
    attack_ids.append(row['Technique_ID'])
embeddings = model.encode(
    attack_docs,
    normalize_embeddings=True,
    show_progress_bar=True,
    batch_size=32
)

with open("attack_embeddings_transformer.pkl", "wb") as f:
    pickle.dump(
        {
            "ids": attack_ids,
            "metadata":attack_metadata,
            "docs": attack_docs,
            "embeddings": embeddings
        },
        f
    )

print("Saved attack_embeddings.pkl")
