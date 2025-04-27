import re
import random
import string
import uuid
from collections import defaultdict
import pandas as pd
import logging

class DataObscurer:
    def __init__(self):
        self.sensitive_fields = [
            'ip', 'email', 'user', 'id', 'name', 'address', 'phone',
            'password', 'token', 'key', 'secret', 'credit', 'card',
            'ssn', 'social', 'security', 'account', 'number', 'pin'
        ]
        self.logger = logging.getLogger(__name__)

    def generate_random_value(self, original_value):
        """Generate a random value of the same type and format as the original value."""
        try:
            if pd.isna(original_value):
                return original_value
            
            if isinstance(original_value, (int, float)):
                # For numbers, generate a random number in a similar range
                if isinstance(original_value, int):
                    return random.randint(1000, 9999)
                else:
                    return round(random.uniform(1000, 9999), 2)
            elif isinstance(original_value, str):
                # For strings, check common patterns
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', original_value):
                    # IP address
                    return f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
                elif re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', original_value):
                    # Email
                    domains = ['example.com', 'test.com', 'demo.com']
                    return f"user{random.randint(1000, 9999)}@{random.choice(domains)}"
                elif re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', original_value):
                    # UUID
                    return str(uuid.uuid4())
                else:
                    # Generic string
                    return ''.join(random.choices(string.ascii_letters + string.digits, k=len(original_value)))
            return original_value
        except Exception as e:
            self.logger.error(f"Error generating random value: {str(e)}")
            return original_value

    def is_sensitive_column(self, column_name):
        """Check if a column name indicates sensitive data."""
        try:
            if not isinstance(column_name, str):
                return False
            column_lower = column_name.lower()
            return any(field in column_lower for field in self.sensitive_fields)
        except Exception as e:
            self.logger.error(f"Error checking sensitive column: {str(e)}")
            return False

    def create_representative_sample(self, df, patterns, sample_size=100):
        """
        Create a representative sample of events based on pattern distribution.
        
        Args:
            df (pd.DataFrame): The original DataFrame containing the log data
            patterns (list): List of pattern dictionaries with 'pattern' and 'count' keys
            sample_size (int): Target size for the representative sample
            
        Returns:
            dict: Contains sample data, pattern statistics, and metadata
        """
        try:
            if not isinstance(df, pd.DataFrame) or df.empty:
                raise ValueError("Invalid or empty DataFrame provided")
                
            if not patterns:
                raise ValueError("No patterns provided")
                
            # Group events by their patterns
            pattern_groups = defaultdict(list)
            for idx, row in df.iterrows():
                row_str = str(row)
                for pattern in patterns:
                    if pattern.get('pattern') and pattern['pattern'] in row_str:
                        pattern_groups[pattern['pattern']].append(idx)
                        break
            
            # Calculate total events and pattern percentages
            total_events = len(df)
            pattern_stats = []
            for pattern, indices in pattern_groups.items():
                count = len(indices)
                percentage = (count / total_events) * 100
                pattern_stats.append({
                    'pattern': pattern,
                    'count': count,
                    'percentage': percentage
                })
            
            # Create representative sample
            sample_indices = []
            for pattern, indices in pattern_groups.items():
                # Calculate how many samples to take for this pattern
                pattern_percentage = len(indices) / total_events
                pattern_sample_size = max(1, int(sample_size * pattern_percentage))
                
                # Randomly select indices for this pattern
                sample_indices.extend(random.sample(indices, min(pattern_sample_size, len(indices))))
            
            # Get the sample data
            sample_df = df.iloc[sample_indices].copy()
            
            # Obscure sensitive data
            for col in sample_df.columns:
                if self.is_sensitive_column(col):
                    sample_df[col] = sample_df[col].apply(self.generate_random_value)
            
            return {
                'sample_data': sample_df.to_dict('records'),
                'pattern_stats': pattern_stats,
                'total_events': total_events,
                'sample_size': len(sample_indices)
            }
        except Exception as e:
            self.logger.error(f"Error creating representative sample: {str(e)}")
            raise

    def process_data(self, df, patterns, sample_size=100):
        """
        Main method to process and obscure the data.
        
        Args:
            df (pd.DataFrame): The original DataFrame
            patterns (list): List of pattern dictionaries
            sample_size (int): Target sample size
            
        Returns:
            dict: Processed and obscured data with statistics
        """
        try:
            result = self.create_representative_sample(df, patterns, sample_size)
            return {
                'success': True,
                'data': result
            }
        except Exception as e:
            self.logger.error(f"Error processing data: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            } 