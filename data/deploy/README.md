# Deployment-model data (not used by the paper)

`param_names.txt` is 6,453 real-world HTTP parameter names from SecLists
`Discovery/Web-Content/burp-parameter-names.txt`
(https://github.com/danielmiessler/SecLists, MIT License, Copyright (c) 2018
Daniel Miessler), pinned at commit `c0d3fb1ff21957bb0458bf0004a9eb6c0597a8d5`.

- SHA-256: `91f7e457415ffd0e4278d13887804036b62240a135a022a6fd6e831a7151899f`

`scripts/train_deploy_models.py` uses it to generate diverse benign training
inputs for the live WAF's models (`models/deploy/`). The paper's training
data has 29 benign parameter names, so the paper models flag ordinary inputs
with unfamiliar names (e.g. `type=1`). A seeded 20% of these names are held
out and used only for evaluation.
