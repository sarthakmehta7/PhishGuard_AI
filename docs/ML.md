# Machine Learning Pipeline

The model uses 30 URL-derived features and a soft-voting ensemble of Random Forest, Gradient Boosting, and Logistic Regression.

Training records:

- dataset SHA-256
- source description
- class distribution
- dropped/invalid rows
- train/test sample counts
- held-out accuracy, precision, recall and weighted F1
- confusion matrix
- stratified cross-validation weighted F1 mean/std
- Random Forest feature importance
- UTC training timestamp
- model version

The training script refuses unsupported labels and does not synthesize missing samples.

## Interpreting metrics

Metrics describe the downloaded dataset and its held-out split. They are not a guarantee of real-world detection performance. Dataset drift, duplicated domains, adversarial URLs, and changes in attacker behavior can reduce performance after deployment.
