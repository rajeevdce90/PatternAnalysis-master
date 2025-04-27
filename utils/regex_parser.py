import re
from typing import List, Dict, Any, Callable, Optional
import logging

logger = logging.getLogger(__name__)

def extract_pattern(log_line: str) -> str:
    """
    Extract a pattern from a log line by replacing variable parts with placeholders.
    
    Args:
        log_line: The log line to analyze
        
    Returns:
        A pattern string with placeholders for variable parts
    """
    # Common patterns to detect and replace
    patterns = [
        (r'\d{1,3}(?:\.\d{1,3}){3}', '<ip>'),  # IP addresses
        (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '<email>'),  # Email addresses
        (r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '<uuid>'),  # UUIDs
        (r'0x[0-9a-fA-F]+', '<hex>'),  # Hexadecimal numbers
        (r'(?<!\d)\d+(?!\d)', '<number>'),  # Numbers
        (r'/[^\s]+', '<path>'),  # File paths
        (r'https?://[^\s]+', '<url>'),  # URLs
        (r'[A-Z][a-z]+ \d{1,2}, \d{4}', '<date>'),  # Dates
        (r'\d{2}:\d{2}:\d{2}', '<time>')  # Times
    ]
    
    pattern = log_line
    for regex, placeholder in patterns:
        pattern = re.sub(regex, placeholder, pattern)
    
    return pattern

class RegexParser:
    def __init__(self):
        self.parsers: List[Callable[[str], Optional[Dict[str, str]]]] = []
        self.patterns: List[Dict[str, Any]] = []
        self.raw_events: List[str] = []

    def _generate_regex_pattern(self, log_pattern: str) -> str:
        """
        Replace placeholders like <ip>, <email>, etc., with regex named groups.
        """
        # Map of placeholder to regex
        patterns = {
            '<ip>': r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})',
            '<email>': r'(?P<email>[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
            '<uuid>': r'(?P<uuid>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})',
            '<number>': r'(?P<number>\d+)',
            '<hex>': r'(?P<hex>0x[0-9a-fA-F]+)',
            '<path>': r'(?P<path>/[^\s]+)',
            '<url>': r'(?P<url>https?://[^\s]+)',
            '<date>': r'(?P<date>[A-Z][a-z]+ \d{1,2}, \d{4})',
            '<time>': r'(?P<time>\d{2}:\d{2}:\d{2})'
        }
        regex_pattern = re.escape(log_pattern)
        # Replace escaped placeholders with regex
        for placeholder, regex in patterns.items():
            regex_pattern = regex_pattern.replace(re.escape(placeholder), regex)
        return '^' + regex_pattern + '$'

    def add_pattern(self, log_pattern: str, example: str) -> None:
        """
        Add a new pattern and its corresponding parser to the list.
        """
        try:
            self.raw_events.append(example)
            regex_pattern = self._generate_regex_pattern(log_pattern)
            compiled = re.compile(regex_pattern)

            def parser(log_line: str) -> Optional[Dict[str, str]]:
                match = compiled.match(log_line)
                if match:
                    result = match.groupdict()
                    result['raw_event'] = log_line
                    return result
                return None

            self.parsers.append(parser)
            self.patterns.append({
                'pattern': log_pattern,
                'regex': regex_pattern,
                'example': example,
                'raw_event': example
            })
            logger.debug(f"Added pattern: {log_pattern} with example: {example}")

        except Exception as e:
            logger.error(f"Error adding pattern {log_pattern}: {str(e)}")
            raise

    def parse_log(self, log_line: str) -> Dict[str, str]:
        """
        Parse a log line using all available parsers.
        """
        for parser in self.parsers:
            result = parser(log_line)
            if result:
                return result
        return {'raw_event': log_line}

    def get_patterns(self) -> List[Dict[str, Any]]:
        return self.patterns

    def clear_patterns(self) -> None:
        self.parsers = []
        self.patterns = []
        self.raw_events = []
        logger.debug("Cleared all patterns and parsers") 