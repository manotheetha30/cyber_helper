import json

with open("train_pairs.json", "r", encoding="utf-8") as f:
    data = json.load(f)

grouped = {}

for item in data:

    key = f"{item['technique_id']}::{item['tactic_name']}"

    if key not in grouped:
        grouped[key] = {
            "technique_id": item["technique_id"],
            "queries": [],
            "technique_name": item["technique_name"],
            "technique_description": item["technique_description"],
            "tactic_name": item["tactic_name"],
            "tactic_description": item["tactic_description"]
        }

    grouped[key]["queries"].append(item["query"])

result = list(grouped.values())
final_dataset=[]
for technique in result:

    passage = f"""
Technique ID: {technique['technique_id']}

Technique Name:
{technique['technique_name']}

Tactic:
{technique['tactic_name']}

Technique Description:
{technique['technique_description']}

Tactic Description:
{technique['tactic_description']}
""".strip()

    for query in technique["queries"]:

        final_dataset.append({
            "query": query.strip(),
            "passage": passage
        })

print(f"Generated {len(final_dataset)} training pairs")

with open(
    "flattened_attack_pairs.json",
    "w",
    encoding="utf-8"
) as f:
    json.dump(
        final_dataset,
        f,
        indent=2,
        ensure_ascii=False
    )
with open("final_training_dataset.json", "w", encoding="utf-8") as f:
    json.dump(result, f, indent=2)