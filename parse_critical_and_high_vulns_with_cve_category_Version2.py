# This script works with CSV exported from Defender - Weakness tab
# It gives you a proper count of Microsoft, non-Microsoft, multi-browsers and single solution, when they are high or critical
# It is useful to report executive level VM to your board

import csv

RELATED_SW_FIELD = 'Related Software'
SEVERITY_FIELD = 'Severity'
CVE_FIELD = 'Name'
OUTPUT_FILE = 'summary_highs_and_critical.csv'
CVE_BY_CATEGORY_FILE = 'cve_by_category.csv'

BROWSER_KEYWORDS = [
    'chrome', 'chromium', 'firefox', 'edge', 'safari', 'opera', 'brave', 'chromedriver', 'chromium-based', 'webview2'
]

def is_browser(product_name):
    name = (product_name or '').lower()
    return any(b in name for b in BROWSER_KEYWORDS)

def parse_related_software(cell):
    items = [x.strip() for x in (cell or '').split(';') if x.strip()]
    pairs = []
    for item in items:
        if ':' in item:
            vendor, product = item.split(':', 1)
            pairs.append((vendor.strip().lower(), product.strip().lower()))
    return pairs

def get_category(row):
    sw_pairs = parse_related_software(row.get(RELATED_SW_FIELD, ''))
    if not sw_pairs:
        return 'Other'
    vendors = set(v for v, p in sw_pairs)
    browser_products = set(p for v, p in sw_pairs if is_browser(p))
    if vendors == {'microsoft'}:
        return 'Microsoft Only'
    elif len(browser_products) >= 2:
        return 'Multiple Browsers'
    elif len(vendors) > 1 and not browser_products:
        return 'Multiple Vendors (not browsers)'
    else:
        return 'Other'

def count_categories(rows):
    counts = {
        'Microsoft Only': 0,
        'Multiple Browsers': 0,
        'Multiple Vendors (not browsers)': 0,
        'Other': 0
    }
    for row in rows:
        cat = get_category(row)
        counts[cat] += 1
    return counts

# Read data, skipping the first row
with open('export-tvm-vulnerabilities_pyme.csv', newline='', encoding='utf-8') as csvfile:
    next(csvfile)
    reader = list(csv.DictReader(csvfile))

critical_rows = [row for row in reader if 'critical' in row.get(SEVERITY_FIELD, '').strip().lower()]
high_rows = [row for row in reader if 'high' in row.get(SEVERITY_FIELD, '').strip().lower()]

crit_counts = count_categories(critical_rows)
high_counts = count_categories(high_rows)

# Print results
print("Critical Vulnerabilities Breakdown:")
for k, v in crit_counts.items():
    print(f"  {k}: {v}")

print("\nHigh Vulnerabilities Breakdown:")
for k, v in high_counts.items():
    print(f"  {k}: {v}")

# Write results to CSV, with 'Severity' column
with open(OUTPUT_FILE, 'w', newline='', encoding='utf-8') as csv_out:
    writer = csv.writer(csv_out)
    writer.writerow(['Severity', 'Category', 'Count'])
    for k, v in crit_counts.items():
        writer.writerow(['Critical', k, v])
    for k, v in high_counts.items():
        writer.writerow(['High', k, v])

print(f"\nSummary written to {OUTPUT_FILE}")

# Write CVE/category pairs to separate CSV
with open(CVE_BY_CATEGORY_FILE, 'w', newline='', encoding='utf-8') as cve_out:
    writer = csv.writer(cve_out)
    writer.writerow(['CVE', 'Category', 'Severity'])
    for row in critical_rows:
        cve = row.get(CVE_FIELD, '').strip()
        category = get_category(row)
        if cve:
            writer.writerow([cve, category, 'Critical'])
    for row in high_rows:
        cve = row.get(CVE_FIELD, '').strip()
        category = get_category(row)
        if cve:
            writer.writerow([cve, category, 'High'])

print(f"Per-CVE category listing written to {CVE_BY_CATEGORY_FILE}")
