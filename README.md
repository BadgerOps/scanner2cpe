# PoC of scanner dedup

The purpose of this program is to compare several security tool outputs that reference a vulnurable php version against the standard CPE format as [seen here](https://nvd.nist.gov/products/cpe/detail/A6ABF754-2521-417F-B610-58515F01F4E5?namingFormat=2.3&amp;orderBy=CPEURI&amp;keyword=package&amp;status=FINAL)

> Note: I'm using the CPE syntax,  but obviously in .json format instead of XML for this PoC

I wanted to learn a little more about how the [RecordLinkage](https://recordlinkage.readthedocs.io/en/latest/index.html) library worked with this program, I'm just barely scratching the surface here so I can wrap my head around how it's working. The fuzzy record matching works fairly well with the contrived data, but, for example ignores the `corp` in `canonical corp` with an `0.85` threshold - bumping that to `0.95` results in the expected low confidence match. I would expect real production data to be more difficult to work through.

I've heavily commented the script as I worked through a few examples & the above linked docs.

### To use:

This was written and tested with python 3.11.8

You can run this by following along:

```bash
python3 -m venv ./venv
source venv/bin/activate
pip install -r requirements.txt

python3 poc.py
```

> NOTE: I include the output of `pip freeze` here - the only 2 packages I installed were pandas and recordlinkage, the rest are deps


#### Log output of program:

```
python3 poc.py
the example CPE data is: 
 {'cpe': 'cpe:2.3:a:canonical:php5:5.3.2-1ubuntu4.16:*:*:*:*:*:*:*', 'vendor': 'canonical', 'product': 'php5', 'version': '5.3.2-1ubuntu4.16', 'vuln': 'CVE-2019-11043'}
security_tool_a has a perfect match: 
 {'product': 'php5', 'version': '5.3.2', 'vendor': 'canonical', 'vuln': 'CVE-2019-11043', 'match': True, 'confidence': 1.0}
security_tool_d has a perfect match: 
 {'product': 'php5', 'version': '5.3.2', 'vendor': 'canonical corp', 'vuln': 'CVE-2019-11043', 'match': True, 'confidence': 1.0}
security_tool_b has a low confidence match: 
 {'product': 'php5', 'version': '5.3.0', 'vendor': 'canonical', 'vuln': 'CVE-2019-11043', 'match': False, 'confidence': 0.75}
security_tool_c does not appear to match: 
 {'product': 'php5', 'version': '5', 'vendor': 'Ubuntu', 'vuln': 'CVE-2019-11043', 'match': False, 'confidence': 0.5}
 ```