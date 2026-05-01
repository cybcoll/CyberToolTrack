# From a file
python incident_extractor.py incident.txt

# From stdin (piping)
cat incident.txt | python incident_extractor.py --stdin

# JSON output for integration
python incident_extractor.py incident.txt --json

# Pipe to JSON
cat incident.txt | python incident_extractor.py --stdin --json > indicators.json