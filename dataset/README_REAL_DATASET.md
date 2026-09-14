# Real Dataset Sources

PhishGuard AI does NOT generate fake phishing URLs.

Run:

    python dataset/download_real_dataset.py

The downloader builds a labelled dataset from public sources:

- OpenPhish community feed: verified phishing URLs (label 2)
- URLhaus recent feed: malicious URLs, used as the Suspicious/Malicious class (label 1)
- Tranco top-sites list: popular domains, used as the legitimate class (label 0)

The exact number of samples depends on the live feeds at download time.
Training metrics are calculated from the downloaded data and are never hard-coded.

Network access is required only for downloading the training data and for optional live
DNS/SSL/HTTP/WHOIS checks.
