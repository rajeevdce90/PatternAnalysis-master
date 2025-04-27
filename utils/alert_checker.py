import time
import threading
import logging
import json
import requests
from datetime import datetime, timedelta
from urllib.parse import urljoin
from models.alert import Alert
from utils.email_sender import email_sender

logger = logging.getLogger(__name__)

class AlertChecker:
    """Utility for checking and triggering alerts based on query results"""
    
    def __init__(self, check_interval=60, opensearch_url='http://localhost:9200'):
        """
        Initialize the alert checker
        
        Args:
            check_interval: Seconds between alert checks
            opensearch_url: Base URL for the OpenSearch instance
        """
        self.check_interval = check_interval
        self.opensearch_url = opensearch_url
        self.sql_endpoint = urljoin(opensearch_url, '_plugins/_sql')
        self.running = False
        self.thread = None
    
    def start(self):
        """Start the alert checking thread"""
        if self.running:
            logger.warning("Alert checker is already running")
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._check_loop)
        self.thread.daemon = True
        self.thread.start()
        logger.info("Started alert checker thread")
    
    def stop(self):
        """Stop the alert checking thread"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=10)
        logger.info("Stopped alert checker thread")
    
    def _check_loop(self):
        """Main loop for checking alerts"""
        while self.running:
            try:
                self.check_alerts()
            except Exception as e:
                logger.error(f"Error checking alerts: {str(e)}")
            
            # Sleep until next check
            time.sleep(self.check_interval)
    
    def check_alerts(self):
        """Check all due alerts"""
        try:
            alerts = Alert.get_due_alerts()
            logger.info(f"Checking {len(alerts)} due alerts")
            
            for alert in alerts:
                try:
                    # Get the query associated with this alert
                    query = self._get_query_by_id(alert.query_id)
                    if not query:
                        logger.error(f"Query not found for alert {alert.id}")
                        continue
                    
                    # Format timestamp for the alert's timespan in ISO 8601 UTC
                    check_from = datetime.utcnow() - timedelta(minutes=alert.timespan)
                    # timestamp = check_from.strftime('%Y-%m-%d %H:%M:%S') # Old format
                    timestamp_iso = check_from.isoformat(timespec='milliseconds') + 'Z'
                    
                    # Format the query with timestamp
                    # formatted_query = self.format_query_with_timestamp(query['query'], timestamp) # Old call
                    formatted_query = self.format_query_with_timestamp(query['query'], timestamp_iso)
                    
                    # Execute the query
                    response = requests.post(
                        self.sql_endpoint,
                        headers={'Content-Type': 'application/json'},
                        json={'query': formatted_query}
                    )
                    
                    if response.status_code != 200:
                        logger.error(f"Query execution failed: {response.text}")
                        continue
                    
                    result = response.json()
                    
                    # Process the results based on alert condition
                    if 'datarows' in result and len(result['datarows']) > 0:
                        # Get the first value from the first row
                        value = float(result['datarows'][0][0])
                        threshold = float(alert.threshold)
                        
                        triggered = False
                        if alert.condition == 'greater_than':
                            triggered = value > threshold
                        elif alert.condition == 'less_than':
                            triggered = value < threshold
                        elif alert.condition == 'equals':
                            triggered = abs(value - threshold) < 0.0001  # For floating point comparison
                        elif alert.condition == 'not_equals':
                            triggered = abs(value - threshold) >= 0.0001
                        
                        if triggered:
                            # Create alert notification
                            Alert.create_notification(
                                alert_id=alert.id,
                                value=value,
                                threshold=threshold,
                                condition=alert.condition,
                                query_result=result
                            )
                    
                    # Update last check time
                    alert.update_last_check()
                    
                except Exception as e:
                    logger.error(f"Error processing alert {alert.id}: {str(e)}")
                    continue
                
        except Exception as e:
            logger.error(f"Error in alert checker: {str(e)}")
    
    def _get_query_by_id(self, query_id):
        """Get query details by ID"""
        import os
        query_file = os.path.join('saved_queries', f"{query_id}.json")
        
        if not os.path.exists(query_file):
            return None
        
        with open(query_file, 'r') as f:
            try:
                return json.load(f)
            except:
                return None
    
    def format_query_with_timestamp(self, query, timestamp_iso):
        """Format a query with a timestamp filter using OpenSearch SQL format."""
        try:
            # Parse the ISO timestamp and convert to epoch milliseconds
            dt = datetime.fromisoformat(timestamp_iso.rstrip('Z'))
            epoch_ms = int(dt.timestamp() * 1000)
            
            # Remove any trailing semicolon
            query = query.strip().rstrip(';')
            
            # Construct the timestamp condition using epoch milliseconds
            timestamp_condition = f"timestamp >= {epoch_ms}"
            
            # Check if query already has a WHERE clause
            where_index = query.upper().find('WHERE')
            if where_index == -1:
                # No WHERE clause, add one before any GROUP BY, ORDER BY, or LIMIT
                for clause in ['GROUP BY', 'ORDER BY', 'LIMIT']:
                    clause_index = query.upper().find(clause)
                    if clause_index != -1:
                        return f"{query[:clause_index]} WHERE {timestamp_condition} {query[clause_index:]}"
                # No existing clauses, add WHERE at the end
                return f"{query} WHERE {timestamp_condition}"
            else:
                # Has WHERE clause, add AND condition
                # Find the next clause after WHERE
                next_clause_index = -1
                for clause in ['GROUP BY', 'ORDER BY', 'LIMIT']:
                    clause_index = query.upper().find(clause, where_index)
                    if clause_index != -1 and (next_clause_index == -1 or clause_index < next_clause_index):
                        next_clause_index = clause_index
                
                if next_clause_index != -1:
                    # Insert timestamp condition before the next clause
                    return f"{query[:next_clause_index]} AND {timestamp_condition} {query[next_clause_index:]}"
                else:
                    # No other clauses, add timestamp condition at the end
                    return f"{query} AND {timestamp_condition}"
                    
        except Exception as e:
            logger.error(f"Error formatting timestamp query: {str(e)}")
            # Return original query if timestamp formatting fails
            return query
    
    def _trigger_alert(self, alert, results):
        """Record the triggered alert and notify recipients"""
        if not results or 'datarows' not in results:
            return
        
        # Get the first result value for the alert record
        result_value = results['datarows'][0][0] if results['datarows'] else None
        result_count = len(results['datarows'])
        
        # Record the triggered alert
        triggered_alert = Alert.add_triggered_alert(
            alert_id=alert.id,
            result_value=result_value,
            result_count=result_count,
            details={
                'schema': results.get('schema', []),
                'sample_rows': results['datarows'][:5] if result_count > 0 else []
            }
        )
        
        # Send notifications to recipients
        self._send_alert_notifications(alert, triggered_alert, results)
        
        logger.info(f"Alert triggered: {alert.name} (ID: {alert.id})")
    
    def _send_alert_notifications(self, alert, triggered_alert, results):
        """Send notifications to alert recipients"""
        if not alert.recipients:
            return
        
        # For simplicity in this implementation, email notification is handled 
        # without accessing User model directly to avoid circular imports
        # In production, you'd import User model or use a service pattern
        
        # Get alert details for email
        alert_name = alert.name
        alert_description = alert.description or "No description"
        triggered_at = datetime.fromisoformat(triggered_alert['triggered_at']).strftime('%Y-%m-%d %H:%M:%S')
        result_count = triggered_alert['result_count'] or 0
        result_value = triggered_alert['result_value']
        
        # Get the query that triggered the alert
        query = self._get_query_by_id(alert.query_id)
        query_name = query['name'] if query else "Unknown query"
        query_text = query['query'] if query else "Query not found"
        
        # Construct email body
        subject = f"Alert Triggered: {alert_name}"
        
        html_content = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 800px; margin: 0 auto; padding: 20px; }}
                .header {{ background-color: #dc3545; color: white; padding: 15px; text-align: center; }}
                .content {{ padding: 20px; }}
                .section {{ margin-bottom: 20px; }}
                .footer {{ text-align: center; margin-top: 20px; font-size: 12px; color: #666; }}
                table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                pre {{ background-color: #f5f5f5; padding: 10px; border-radius: 4px; overflow-x: auto; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h2>Alert Triggered: {alert_name}</h2>
                </div>
                <div class="content">
                    <div class="section">
                        <h3>Alert Details</h3>
                        <p><strong>Description:</strong> {alert_description}</p>
                        <p><strong>Triggered At:</strong> {triggered_at}</p>
                        <p><strong>Result Count:</strong> {result_count} rows</p>
                        <p><strong>Result Value:</strong> {result_value}</p>
                    </div>
                    
                    <div class="section">
                        <h3>Query Information</h3>
                        <p><strong>Query Name:</strong> {query_name}</p>
                        <pre>{query_text}</pre>
                    </div>
        """
        
        # Add sample results if available
        if results and 'schema' in results and 'datarows' in results and results['datarows']:
            html_content += """
                    <div class="section">
                        <h3>Sample Results</h3>
                        <table>
                            <thead>
                                <tr>
            """
            
            # Add table headers
            for column in results['schema']:
                column_name = column.get('name', 'Unknown')
                html_content += f"<th>{column_name}</th>\n"
            
            html_content += """
                                </tr>
                            </thead>
                            <tbody>
            """
            
            # Add sample rows (up to 5)
            for row in results['datarows'][:5]:
                html_content += "<tr>\n"
                for cell in row:
                    html_content += f"<td>{cell}</td>\n"
                html_content += "</tr>\n"
            
            html_content += """
                            </tbody>
                        </table>
                    </div>
            """
        
        # Close HTML
        html_content += """
                </div>
                <div class="footer">
                    This is an automated alert notification from the Zamuun Analysis Dashboard.
                </div>
            </div>
        </body>
        </html>
        """
        
        # Send to each recipient
        for recipient_id in alert.recipients:
            user = User.get_user_by_id(recipient_id)
            if user and user.email:
                email_sender.send_email(user.email, subject, html_content)
                logger.info(f"Sent alert notification to {user.email}")

# Create a singleton instance
alert_checker = AlertChecker() 