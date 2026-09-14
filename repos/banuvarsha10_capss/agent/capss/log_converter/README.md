# Log Converter Module

This module provides the `LogConverter` class to parse Open5GS and UERANSIM log files and extract Registration Request events into a structured CSV format.

## Classes
- `LogConverter`: Main class for log conversion.

### Methods:
- `convert_log_file(log_path, output_path)`: Reads a log file, extracts registration events, and writes them to a CSV file. Returns the path to the output CSV.
- `parse_log_entry(line)`: Parses a single log line using regex. Returns a dictionary if matched, else `None`.
- `parse_log_block(lines)`: Parses a block of log lines and returns a list of dictionaries.

## Dependencies
- `re`, `csv`, `os`, `datetime`

## Example Usage
```python
from capss.log_converter import LogConverter

converter = LogConverter()
csv_file = converter.convert_log_file("amf.log", "registrations.csv")
print(f"Extracted events to {csv_file}")
```
