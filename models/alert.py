import json
import os
import uuid
from datetime import datetime, timedelta

class Alert:
    """Alert model for storing alert configurations and triggered alerts"""
    
    ALERTS_FILE = os.path.join('settings', 'alerts.json')
    TRIGGERED_ALERTS_FILE = os.path.join('settings', 'triggered_alerts.json')
    
    def __init__(self, name, query_id, threshold=None, condition="greater_than", frequency=15, 
                 status="active", alert_id=None, created_by=None, created_at=None, 
                 last_triggered=None, recipients=None, description=None, timespan=60):
        self.id = alert_id or str(uuid.uuid4())
        self.name = name
        self.description = description or ""
        self.query_id = query_id
        self.threshold = threshold  # Numerical threshold for alert condition
        self.condition = condition  # "greater_than", "less_than", "equal_to", "not_equal_to", "contains"
        self.frequency = frequency  # Minutes between alert checks
        self.timespan = timespan    # Minutes of data to consider
        self.status = status        # "active", "disabled", "deleted"
        self.created_by = created_by
        self.created_at = created_at or datetime.now().isoformat()
        self.last_triggered = last_triggered
        self.recipients = recipients or []  # List of user IDs to notify
    
    def to_dict(self):
        """Convert alert object to dictionary for storage"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'query_id': self.query_id,
            'threshold': self.threshold,
            'condition': self.condition,
            'frequency': self.frequency,
            'timespan': self.timespan,
            'status': self.status,
            'created_by': self.created_by,
            'created_at': self.created_at,
            'last_triggered': self.last_triggered,
            'recipients': self.recipients
        }
    
    @classmethod
    def from_dict(cls, data):
        """Create an alert object from dictionary data"""
        return cls(
            name=data['name'],
            query_id=data['query_id'],
            threshold=data.get('threshold'),
            condition=data.get('condition', 'greater_than'),
            frequency=data.get('frequency', 15),
            timespan=data.get('timespan', 60),
            status=data.get('status', 'active'),
            alert_id=data['id'],
            created_by=data.get('created_by'),
            created_at=data.get('created_at'),
            last_triggered=data.get('last_triggered'),
            recipients=data.get('recipients', []),
            description=data.get('description', '')
        )
    
    @classmethod
    def get_all_alerts(cls):
        """Get all alerts from the JSON file"""
        if not os.path.exists(cls.ALERTS_FILE):
            return []
        
        with open(cls.ALERTS_FILE, 'r') as f:
            try:
                alerts_data = json.load(f)
                return [cls.from_dict(alert_data) for alert_data in alerts_data]
            except:
                return []
    
    @classmethod
    def get_alert_by_id(cls, alert_id):
        """Get an alert by its ID"""
        alerts = cls.get_all_alerts()
        for alert in alerts:
            if alert.id == alert_id:
                return alert
        return None
    
    @classmethod
    def get_alerts_by_query_id(cls, query_id):
        """Get all alerts associated with a specific query"""
        alerts = cls.get_all_alerts()
        return [alert for alert in alerts if alert.query_id == query_id]
    
    @classmethod
    def get_alerts_by_user(cls, user_id):
        """Get all alerts created by a specific user"""
        alerts = cls.get_all_alerts()
        return [alert for alert in alerts if alert.created_by == user_id]
    
    @classmethod
    def create_alert(cls, name, query_id, threshold=None, condition="greater_than", 
                    frequency=15, status="active", created_by=None, recipients=None, 
                    description=None, timespan=60):
        """Create a new alert and save to JSON file"""
        alert = cls(
            name=name,
            query_id=query_id,
            threshold=threshold,
            condition=condition,
            frequency=frequency,
            timespan=timespan,
            status=status,
            created_by=created_by,
            recipients=recipients,
            description=description
        )
        
        # Save to file
        alerts = cls.get_all_alerts()
        alerts.append(alert)
        cls._save_alerts(alerts)
        
        return alert
    
    @classmethod
    def update_alert(cls, alert_id, **kwargs):
        """Update alert attributes"""
        alert = cls.get_alert_by_id(alert_id)
        if not alert:
            return False
        
        # Update attributes
        for key, value in kwargs.items():
            if hasattr(alert, key):
                setattr(alert, key, value)
        
        # Save changes
        alerts = cls.get_all_alerts()
        for i, existing_alert in enumerate(alerts):
            if existing_alert.id == alert_id:
                alerts[i] = alert
                break
        
        cls._save_alerts(alerts)
        return True
    
    @classmethod
    def delete_alert(cls, alert_id):
        """Delete an alert (or mark as deleted)"""
        alert = cls.get_alert_by_id(alert_id)
        if not alert:
            return False
        
        # Mark as deleted instead of removing completely
        alert.status = 'deleted'
        
        # Save changes
        alerts = cls.get_all_alerts()
        for i, existing_alert in enumerate(alerts):
            if existing_alert.id == alert_id:
                alerts[i] = alert
                break
        
        cls._save_alerts(alerts)
        return True
    
    @classmethod
    def _save_alerts(cls, alerts):
        """Save alerts list to JSON file"""
        # Ensure directory exists
        os.makedirs(os.path.dirname(cls.ALERTS_FILE), exist_ok=True)
        
        # Save to file
        with open(cls.ALERTS_FILE, 'w') as f:
            json.dump([alert.to_dict() for alert in alerts], f, indent=2)
    
    @classmethod
    def add_triggered_alert(cls, alert_id, result_value, result_count=None, details=None):
        """Record a triggered alert instance"""
        triggered_alert = {
            'id': str(uuid.uuid4()),
            'alert_id': alert_id,
            'triggered_at': datetime.now().isoformat(),
            'result_value': result_value,
            'result_count': result_count,
            'details': details or {}
        }
        
        # Get existing triggered alerts
        triggered_alerts = cls.get_triggered_alerts()
        
        # Add new alert to list
        triggered_alerts.append(triggered_alert)
        
        # Update the last_triggered time for the alert
        alert = cls.get_alert_by_id(alert_id)
        if alert:
            alert.last_triggered = triggered_alert['triggered_at']
            cls.update_alert(alert_id, last_triggered=alert.last_triggered)
        
        # Save to file
        cls._save_triggered_alerts(triggered_alerts)
        return triggered_alert
    
    @classmethod
    def get_triggered_alerts(cls, limit=1000, alert_id=None, from_date=None, to_date=None):
        """Get triggered alert instances with optional filtering"""
        if not os.path.exists(cls.TRIGGERED_ALERTS_FILE):
            return []
        
        with open(cls.TRIGGERED_ALERTS_FILE, 'r') as f:
            try:
                triggered_alerts = json.load(f)
                
                # Apply filters
                if alert_id:
                    triggered_alerts = [a for a in triggered_alerts if a['alert_id'] == alert_id]
                
                if from_date:
                    from_dt = datetime.fromisoformat(from_date)
                    triggered_alerts = [a for a in triggered_alerts if datetime.fromisoformat(a['triggered_at']) >= from_dt]
                
                if to_date:
                    to_dt = datetime.fromisoformat(to_date)
                    triggered_alerts = [a for a in triggered_alerts if datetime.fromisoformat(a['triggered_at']) <= to_dt]
                
                # Sort by triggered time (newest first) and limit results
                triggered_alerts.sort(key=lambda x: x['triggered_at'], reverse=True)
                return triggered_alerts[:limit]
            except:
                return []
    
    @classmethod
    def _save_triggered_alerts(cls, triggered_alerts):
        """Save triggered alerts to JSON file"""
        # Ensure directory exists
        os.makedirs(os.path.dirname(cls.TRIGGERED_ALERTS_FILE), exist_ok=True)
        
        # Limit file size by keeping only the most recent alerts (e.g., 10000)
        if len(triggered_alerts) > 10000:
            triggered_alerts.sort(key=lambda x: x['triggered_at'], reverse=True)
            triggered_alerts = triggered_alerts[:10000]
        
        # Save to file
        with open(cls.TRIGGERED_ALERTS_FILE, 'w') as f:
            json.dump(triggered_alerts, f, indent=2)
    
    @classmethod
    def get_due_alerts(cls):
        """Get alerts that are due to be checked (based on their frequency)"""
        alerts = cls.get_all_alerts()
        now = datetime.now()
        due_alerts = []
        
        for alert in alerts:
            # Skip inactive alerts
            if alert.status != 'active':
                continue
            
            # If never triggered, it's due
            if not alert.last_triggered:
                due_alerts.append(alert)
                continue
            
            # Check if enough time has passed since last trigger
            last_triggered = datetime.fromisoformat(alert.last_triggered)
            time_since_last = (now - last_triggered).total_seconds() / 60  # in minutes
            
            if time_since_last >= alert.frequency:
                due_alerts.append(alert)
        
        return due_alerts 