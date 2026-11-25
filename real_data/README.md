# Real data

`creditcard_sample.csv` is a sample of the public "Credit Card Fraud Detection" dataset: real card transactions by European cardholders (two days, September 2013), collected by Worldline and the ULB Machine Learning Group.

- Licence: Open Database License 1.0 (database), contents under the Database Contents License. Also on OpenML as `creditcard` (licence "Public").
- Citation: Dal Pozzolo, Caelen, Johnson, Bontempi. Calibrating Probability with Undersampling for Unbalanced Classification. IEEE SSCI 2015.
- The bank hid the original fields, so V1-V28 are PCA components. Only Time, Amount and Class are readable.
- The sample keeps all 492 frauds and about 6,000 evenly spaced legitimate rows (`tools/make_sample.py`). That makes fraud look far more common than the real 0.17%, so use the full file for honest numbers:

```bash
curl -O https://storage.googleapis.com/download.tensorflow.org/data/creditcard.csv   # about 150 MB
python3 -m banksoc cardfraud creditcard.csv
```

No real bank's customer or transaction data is in this repo, and none is available publicly. The simulator in `banksoc/simulator.py` stays synthetic and is labelled as such.
