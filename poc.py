#!/usr/bin/env python

# python3.11 was used for this example

# using https://medium.com/@tubelwj/recordlinkage-a-powerful-python-library-for-data-matching-and-de-duplication-8e319e4142b4 
# and https://brightinventions.pl/blog/data-deduplication-in-python-with-recordlinkage/ as references
# along with https://pypi.org/project/recordlinkage/ and https://pandas.pydata.org/pandas-docs/stable/reference/api/pandas.DataFrame.html
# targeting example CPE data for php5.3.2: https://nvd.nist.gov/products/cpe/detail/A6ABF754-2521-417F-B610-58515F01F4E5?namingFormat=2.3&amp;orderBy=CPEURI&amp;keyword=package&amp;status=FINAL

# example base datastructure is as follows:
# this is very simplified, I don't know exactly what this data will look like coming out of splunk, so I contrived this example based off brief conversation.
# create an initial json example with several "security tools" that have identified a vulnerability in the php5.3.2 package

json_data = {"security_tool_a": {"vendor": "canonical", "product": "php5", "version": "5.3.2", "vuln": "CVE-2019-11043"}, 
             "security_tool_b": {"vendor": "canonical", "product": "php5", "version": "5.3.0", "vuln": "CVE-2019-11043"}, 
             "security_tool_c": {"vendor": "Ubuntu", "product": "php5", "version": "5", "vuln": "CVE-2019-11043"}, 
             "security_tool_d": {"vendor": "canonical corp", "product": "php5", "version": "5.3.2", "vuln": "CVE-2019-11043"}, 
             }
# also create a CPE data structure to compare against, as the "correct" form of the data
cpe_data = {"cpe": {"cpe": "cpe:2.3:a:canonical:php5:5.3.2-1ubuntu4.16:*:*:*:*:*:*:*", "vendor": "canonical", "product": "php5", "version": "5.3.2-1ubuntu4.16", "vuln": "CVE-2019-11043"}}

# keeping this script flat, no need to break it out into functions or classes for this PoC
import json
import pandas as pd
import recordlinkage
# https://recordlinkage.readthedocs.io/en/latest/ref-preprocessing.html - we can clean whitespace/remove punctuation with this module
# if we update the data with real data that may include these, we can use this to clean it up
#from recordlinkage.preprocessing import clean


# Create a series of pandas dataframes from the json data, using the keys as the pandas dataframe identifier and the values as the data
scanner_df = {key: pd.DataFrame(value, index=[0]) for key, value in json_data.items()}
# Create another dataframe of the example CPE data structure
cpe_df = pd.DataFrame(cpe_data['cpe'], index=[0])



# Build an index - use 'product' as the blocking key (note, this is assuming product matches - we'll likely have to adjust this)
# ref https://recordlinkage.readthedocs.io/en/latest/ref-index.html
indexer = recordlinkage.Index()
indexer.block('product')

# now we need to compare the data - ref https://recordlinkage.readthedocs.io/en/latest/ref-compare.html
# using the simple jarowinkler method since we get an easy to work with 0/1 result
# https://en.wikipedia.org/wiki/Jaro%E2%80%93Winkler_distance
# may be worth digging in more to see how other methods compare, but we're basically just fuzzy matching strings in this PoC

compare = recordlinkage.Compare()

compare.string('product', 'product', method='jarowinkler', threshold=0.85, label='product')
compare.string('version', 'version', method='jarowinkler', threshold=0.85, label='version')
compare.string('vendor', 'vendor', method='jarowinkler', threshold=0.85, label='vendor')
compare.string('vuln', 'vuln', method='jarowinkler', threshold=0.85, label='vuln')

# create results dict to store the comparision data
results = {}
# Perform pairwise comparisons against the cpe data, iterateing over each scanner in a loop
for df_name1, df1 in scanner_df.items():
    candidate_links = indexer.index(df1, cpe_df)
    features = compare.compute(candidate_links, df1, cpe_df)
    # Add the comparison results to the dict - using the scanner as the key so we can use it later
    results[df_name1] = features

# Combine all the results into a single dataframe
result = pd.concat(results)

# Find the results that have at least 2 matches and update the matches index
matches = result[result.sum(axis=1) >= 2].reset_index()
matches = matches.set_index(['level_0', 'level_1'])


# finally, build output dict which we could ostensibly use to generate a report, or send to another system
# Here, we're just going to print it out with confidence match levels
output = {}
output['scanners'] = {}
output['cpe'] = cpe_data['cpe']
for i, row in matches.iterrows():
    output['scanners'][i[0]] = {}
    output['scanners'][i[0]]['product'] = scanner_df[i[0]].loc[0, 'product']
    output['scanners'][i[0]]['version'] = scanner_df[i[0]].loc[0, 'version']
    output['scanners'][i[0]]['vendor'] = scanner_df[i[0]].loc[0, 'vendor']
    output['scanners'][i[0]]['vuln'] = scanner_df[i[0]].loc[0, 'vuln']
    output['scanners'][i[0]]['match'] = row.sum() >= 3 # we'll consider ~3 matches to be a match
    output['scanners'][i[0]]['confidence'] = row.sum() / 4

print(f"the example CPE data is: \n {output['cpe']}")
# we're going to sort on confidence level, and print from highest confidence to lowest
# using https://docs.python.org/3.11/howto/sorting.html#key-functions to key off 'confidence'
for k,v in sorted(output['scanners'].items(), key=lambda x: x[1]['confidence'], reverse=True):
    if v['confidence'] == 1:
        print(f"{k} has a perfect match: \n {v}")
    elif v['confidence'] >= 0.85:
        print(f"{k} has a high confidence match: \n {v}")
    elif v['confidence'] >= 0.75:
        print(f"{k} has a low confidence match: \n {v}")
    else:
        print(f"{k} does not appear to match: \n {v}")
