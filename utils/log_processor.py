import pandas as pd
from typing import Tuple, Dict, Any
import json

def process_log_file(filepath: str) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Process uploaded log file and return DataFrame and initial analysis.
    
    Args:
        filepath: Path to the uploaded log file
        
    Returns:
        Tuple containing (DataFrame, analysis_results)
    """
    # Read file based on extension
    if filepath.endswith('.csv'):
        df = pd.read_csv(filepath)
    elif filepath.endswith('.json'):
        df = pd.read_json(filepath)
    else:
        raise ValueError("Unsupported file format")
    
    # Basic analysis
    analysis = {
        'total_rows': len(df),
        'columns': list(df.columns),
        'text_columns': list(df.select_dtypes(include=['object']).columns),
        'numeric_columns': list(df.select_dtypes(include=['int64', 'float64']).columns),
        'sample_rows': df.head(5).to_dict('records')
    }
    
    return df, analysis 