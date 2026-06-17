import pandas as pd

df1 = pd.read_excel("enterprise-attack-techniques.xlsx")
df2 = pd.read_excel("enterprise-attack-tactics.xlsx")
df1 = df1.rename(columns={"ID":"Technique_ID","name":"Technique_Name","description":"Technique_Description",
    "description": "Technique_Description","sub-technique of":"Parent Technique","tactics":"Tactic_Name","platforms":"Platforms "
})

df2 = df2.rename(columns={"name":"Tactic_Name","ID":"Tactic_ID",
    "description": "Tactic_Description"
})
df1 = df1[["Technique_ID", "Technique_Name", "Technique_Description","Tactic_Name","Platforms ","Parent Technique"]]
df2 = df2[["Tactic_ID", "Tactic_Name", "Tactic_Description"]]
# Split tactic column into lists
df1["Tactic_Name"] = df1["Tactic_Name"].str.split(",")
# Create new row for each tactic
df1 = df1.explode("Tactic_Name")
# Remove extra spaces
df1["Tactic_Name"] = df1["Tactic_Name"].str.strip()
result = pd.merge(
    df1,
    df2,
    left_on="Tactic_Name",   # column in file1
    right_on="Tactic_Name",    # column in file2
    how="left"
)


result.to_excel("output.xlsx", index=False)

print("Output saved to output.xlsx")