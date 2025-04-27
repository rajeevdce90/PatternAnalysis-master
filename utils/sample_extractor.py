import pandas as pd
from typing import List, Dict, Any
from .pattern_analyzer import analyze_patterns

def extract_samples(df: pd.DataFrame, column_name: str, sample_size: int = 5) -> List[Dict[str, Any]]:
    """
    Extract representative samples for each pattern in the data.
    
    Args:
        df: DataFrame containing the log data
        column_name: Name of the column containing log messages
        sample_size: Number of samples to extract per pattern
        
    Returns:
        List of dictionaries containing pattern information and samples
    """
    log_lines = df[column_name].dropna().tolist()
    
    # Get unique patterns
    patterns = analyze_patterns(log_lines)
    pattern_dict = {pattern: [] for _, pattern in patterns}
    
    # Collect samples for each pattern
    for line in log_lines:
        if not line or not isinstance(line, str):
            continue
            
        # Get pattern for the line
        line_patterns = analyze_patterns([line])
        if not line_patterns:
            continue
            
        pattern = line_patterns[0][1]
        if pattern in pattern_dict and len(pattern_dict[pattern]) < sample_size:
            pattern_dict[pattern].append(line)
    
    # Format results
    results = []
    for pattern, samples in pattern_dict.items():
        results.append({
            'pattern': pattern,
            'samples': samples,
            'total_matches': len([line for line in log_lines 
                                if line and not pd.isna(line) and 
                                analyze_patterns([line])[0][1] == pattern])
        })
    
    # Sort by frequency
    results.sort(key=lambda x: x['total_matches'], reverse=True)
    
    return results 