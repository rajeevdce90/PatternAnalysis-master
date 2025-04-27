from typing import List, Tuple
import re
from .regex_parser import extract_pattern

def analyze_patterns(log_lines: List[str]) -> List[Tuple[str, str]]:
    """
    Analyze patterns in log lines and return a list of (sample, pattern) tuples.
    
    Args:
        log_lines: List of log lines to analyze
        
    Returns:
        List of tuples containing (sample_line, pattern)
    """
    patterns = []
    seen_patterns = set()
    
    for line in log_lines:
        if not line or not isinstance(line, str):
            continue
            
        # Extract pattern for the line
        pattern = extract_pattern(line)
        
        # Only add unique patterns
        if pattern not in seen_patterns:
            patterns.append((line, pattern))
            seen_patterns.add(pattern)
    
    return patterns 