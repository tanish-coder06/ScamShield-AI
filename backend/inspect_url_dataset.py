from urllib.parse import urlsplit

import pandas as pd
from ucimlrepo import fetch_ucirepo


DATASET_ID = 967

TARGET_HOSTNAMES = {
    "example.com",
    "www.example.com",
    "example.org",
    "www.example.org",
    "example.net",
    "www.example.net",
}


def get_hostname(url: str) -> str:
    """Extract the hostname without visiting the URL."""

    try:
        candidate = url if "://" in url else "//" + url
        parsed = urlsplit(candidate)
        return (parsed.hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def main():
    print("=" * 65)
    print("SCAMSHIELD AI - URL DATASET INSPECTION")
    print("=" * 65)

    # 1. Load the dataset.
    print("\n[1/4] Loading UCI dataset...")

    dataset = fetch_ucirepo(id=DATASET_ID)

    urls = dataset.data.features["URL"]
    labels = dataset.data.targets["label"]

    # Remove records with missing URLs or labels.
    valid = urls.notna() & labels.notna()

    urls = urls[valid].reset_index(drop=True)
    labels = labels[valid].astype(int).reset_index(drop=True)

    print("Total usable records:", len(urls))

    # 2. Display label distribution.
    print("\n[2/4] Dataset label counts:")
    print(labels.value_counts().sort_index())

    print("\nConfigured project label mapping:")
    print("Label 0 = Phishing (verify against dataset documentation)")
    print("Label 1 = Legitimate (verify against dataset documentation)")

    # 3. Search for example-domain text anywhere in each URL.
    print("\n[3/4] Searching for example-domain text...")

    text_mask = urls.astype(str).str.contains(
        r"example\.(?:com|org|net)",
        case=False,
        regex=True,
        na=False,
    )

    print("URLs containing example-domain text:", int(text_mask.sum()))

    if text_mask.any():
        text_matches = pd.DataFrame({
            "URL": urls[text_mask],
            "Label": labels[text_mask],
        })

        print("\nFirst 15 text matches:")
        print(text_matches.head(15).to_string(index=False))
    else:
        print("No example-domain text matches found.")

    # 4. Check whether these are actual hostnames.
    print("\n[4/4] Checking exact hostnames...")

    hostnames = urls.astype(str).apply(get_hostname)

    hostname_mask = hostnames.isin(TARGET_HOSTNAMES)

    print("Exact hostname matches:", int(hostname_mask.sum()))

    if hostname_mask.any():
        hostname_matches = pd.DataFrame({
            "URL": urls[hostname_mask],
            "Hostname": hostnames[hostname_mask],
            "Label": labels[hostname_mask],
        })

        print("\nExact hostname matches:")
        print(hostname_matches.head(30).to_string(index=False))

        print("\nLabel distribution for exact hostname matches:")
        print(hostname_matches["Label"].value_counts().sort_index())
    else:
        print(
            "No exact hostname matches found for "
            "example.com, example.org, or example.net."
        )

    print("\n" + "=" * 65)
    print("DATASET INSPECTION COMPLETE")
    print("No model was trained or overwritten.")
    print("=" * 65)


if __name__ == "__main__":
    main()