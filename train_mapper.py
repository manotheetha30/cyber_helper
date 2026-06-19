from sklearn.model_selection import train_test_split
from sentence_transformers import InputExample,losses,SentenceTransformer

model=SentenceTransformer(
    "BAAI/bge-small-en-v1.5"
)
import json
with open("flattened_attack_pairs.json","r",encoding="utf-8") as f:
    flattened=json.load(f)[:2000]
train_data, val_data = train_test_split(
    flattened,
    test_size=0.1,
    random_state=42
)
train_examples = []

for row in flattened:

    train_examples.append(
        InputExample(
            texts=[
                f"query: {row['query']}",
                f"passage: {row['passage']}"
            ]
        )
    )

from torch.utils.data import DataLoader

train_loader = DataLoader(
    train_examples,
    shuffle=True,
    batch_size=16,pin_memory=False
)


train_loss = losses.MultipleNegativesRankingLoss(
    model
)
warmup_steps = int(
    len(train_loader) * 0.1
)

model.fit(
    train_objectives=[
        (train_loader, train_loss)
    ],
    epochs=1,
    warmup_steps=warmup_steps,
    output_path="./e5_attack_mapper"
)