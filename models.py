import json
import os
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import pyotp
import secrets
import string

class User:
    """User model for authentication and authorization"""
    
    USERS_FILE = os.path.join('settings', 'users.json')
    
    def __init__(self, username, email, password=None, role_id=None, user_id=None, created_at=None, is_active=True, 
                 otp_secret=None, otp_enabled=False, reset_token=None, reset_token_expiry=None, is_temp_password=False):
        self.id = user_id or str(uuid.uuid4())
        self.username = username
        self.email = email
        self.password_hash = generate_password_hash(password) if password else None
        self.role_id = role_id
        self.created_at = created_at or datetime.now().isoformat()
        self.is_active = is_active
        self.otp_secret = otp_secret
        self.otp_enabled = otp_enabled
        self.reset_token = reset_token
        self.reset_token_expiry = reset_token_expiry
        self.is_temp_password = is_temp_password
    
    def check_password(self, password):
        """Check if the provided password matches the stored hash"""
        return check_password_hash(self.password_hash, password)
    
    def generate_otp_secret(self):
        """Generate a new OTP secret key"""
        self.otp_secret = pyotp.random_base32()
        return self.otp_secret
    
    def verify_otp(self, otp_code):
        """Verify an OTP code against the user's secret"""
        if not self.otp_secret:
            return False
        
        totp = pyotp.TOTP(self.otp_secret)
        return totp.verify(otp_code)
    
    def get_otp_uri(self):
        """Get OTP URI for QR code generation"""
        if not self.otp_secret:
            return None
        
        app_name = "Zamuun Analysis"
        totp = pyotp.TOTP(self.otp_secret)
        return totp.provisioning_uri(name=self.email, issuer_name=app_name)
    
    def generate_password_reset_token(self, expiry_hours=24):
        """Generate a unique password reset token that expires in the specified hours"""
        token = secrets.token_urlsafe(32)
        expiry = (datetime.now() + timedelta(hours=expiry_hours)).isoformat()
        
        self.reset_token = token
        self.reset_token_expiry = expiry
        
        return token
    
    def is_reset_token_valid(self, token):
        """Check if a given reset token is valid and not expired"""
        if not self.reset_token or self.reset_token != token:
            return False
            
        if not self.reset_token_expiry:
            return False
            
        expiry_date = datetime.fromisoformat(self.reset_token_expiry)
        return datetime.now() <= expiry_date
    
    def clear_reset_token(self):
        """Clear the reset token after it has been used"""
        self.reset_token = None
        self.reset_token_expiry = None
    
    def generate_temp_password(self, length=12):
        """Generate a temporary random password"""
        alphabet = string.ascii_letters + string.digits
        temp_password = ''.join(secrets.choice(alphabet) for _ in range(length))
        
        # Set the password and mark it as temporary
        self.password_hash = generate_password_hash(temp_password)
        self.is_temp_password = True
        
        return temp_password
    
    def to_dict(self):
        """Convert user object to dictionary for storage"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'password_hash': self.password_hash,
            'role_id': self.role_id,
            'created_at': self.created_at,
            'is_active': self.is_active,
            'otp_secret': self.otp_secret,
            'otp_enabled': self.otp_enabled,
            'reset_token': self.reset_token,
            'reset_token_expiry': self.reset_token_expiry,
            'is_temp_password': self.is_temp_password
        }
    
    @classmethod
    def from_dict(cls, data):
        """Create a user object from dictionary data"""
        user = cls(
            username=data['username'],
            email=data['email'],
            user_id=data['id'],
            role_id=data['role_id'],
            created_at=data['created_at'],
            is_active=data.get('is_active', True),
            otp_secret=data.get('otp_secret'),
            otp_enabled=data.get('otp_enabled', False),
            reset_token=data.get('reset_token'),
            reset_token_expiry=data.get('reset_token_expiry'),
            is_temp_password=data.get('is_temp_password', False)
        )
        user.password_hash = data['password_hash']
        return user
    
    @classmethod
    def get_all_users(cls):
        """Get all users from the JSON file"""
        if not os.path.exists(cls.USERS_FILE):
            return []
        
        with open(cls.USERS_FILE, 'r') as f:
            try:
                users_data = json.load(f)
                return [cls.from_dict(user_data) for user_data in users_data]
            except:
                return []
    
    @classmethod
    def get_user_by_id(cls, user_id):
        """Get a user by their ID"""
        users = cls.get_all_users()
        for user in users:
            if user.id == user_id:
                return user
        return None
    
    @classmethod
    def get_user_by_username(cls, username):
        """Get a user by their username"""
        users = cls.get_all_users()
        for user in users:
            if user.username == username:
                return user
        return None
    
    @classmethod
    def get_user_by_email(cls, email):
        """Get a user by their email"""
        users = cls.get_all_users()
        for user in users:
            if user.email == email:
                return user
        return None
    
    @classmethod
    def create_user(cls, username, email, password, role_id=None):
        """Create a new user and save to JSON file"""
        # Check if user already exists
        if cls.get_user_by_username(username) or cls.get_user_by_email(email):
            return None
        
        # Create new user
        user = cls(username=username, email=email, password=password, role_id=role_id)
        
        # Save to file
        users = cls.get_all_users()
        users.append(user)
        cls._save_users(users)
        
        return user
    
    @classmethod
    def update_user(cls, user_id, **kwargs):
        """Update user attributes"""
        user = cls.get_user_by_id(user_id)
        if not user:
            return False
        
        # Update attributes
        for key, value in kwargs.items():
            if key == 'password':
                user.password_hash = generate_password_hash(value)
            elif hasattr(user, key):
                setattr(user, key, value)
        
        # Save changes
        users = cls.get_all_users()
        for i, existing_user in enumerate(users):
            if existing_user.id == user_id:
                users[i] = user
                break
        
        cls._save_users(users)
        return True
    
    @classmethod
    def delete_user(cls, user_id):
        """Delete a user"""
        users = cls.get_all_users()
        users = [user for user in users if user.id != user_id]
        cls._save_users(users)
        return True
    
    @classmethod
    def _save_users(cls, users):
        """Save users list to JSON file"""
        # Ensure directory exists
        os.makedirs(os.path.dirname(cls.USERS_FILE), exist_ok=True)
        
        # Save to file
        with open(cls.USERS_FILE, 'w') as f:
            json.dump([user.to_dict() for user in users], f, indent=2)
    
    def get_role(self):
        """Get the role associated with this user"""
        if not self.role_id:
            return None
        return Role.get_role_by_id(self.role_id)


class Role:
    """Role model for user permissions"""
    
    ROLES_FILE = os.path.join('settings', 'roles.json')
    
    def __init__(self, name, description=None, tag_access=None, role_id=None):
        self.id = role_id or str(uuid.uuid4())
        self.name = name
        self.description = description or ""
        self.tag_access = tag_access or []  # List of tag IDs this role has access to
    
    def to_dict(self):
        """Convert role object to dictionary for storage"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'tag_access': self.tag_access
        }
    
    @classmethod
    def from_dict(cls, data):
        """Create a role object from dictionary data"""
        return cls(
            name=data['name'],
            description=data.get('description', ''),
            tag_access=data.get('tag_access', []),
            role_id=data['id']
        )
    
    @classmethod
    def get_all_roles(cls):
        """Get all roles from the JSON file"""
        if not os.path.exists(cls.ROLES_FILE):
            # Create default roles if file doesn't exist
            admin_role = cls('Administrator', 'Full system access with all permissions')
            user_role = cls('User', 'Regular user with limited access')
            
            # Get all available tags
            tag_ids = []
            if os.path.exists(os.path.join('settings', 'tags.json')):
                with open(os.path.join('settings', 'tags.json'), 'r') as f:
                    try:
                        tags = json.load(f)
                        tag_ids = [tag['id'] for tag in tags]
                    except:
                        pass
            
            # Admin has access to all tags
            admin_role.tag_access = tag_ids
            # User role starts with no tag access
            
            # Save default roles
            cls._save_roles([admin_role, user_role])
            return [admin_role, user_role]
        
        with open(cls.ROLES_FILE, 'r') as f:
            try:
                roles_data = json.load(f)
                return [cls.from_dict(role_data) for role_data in roles_data]
            except:
                return []
    
    @classmethod
    def get_role_by_id(cls, role_id):
        """Get a role by its ID"""
        roles = cls.get_all_roles()
        for role in roles:
            if role.id == role_id:
                return role
        return None
    
    @classmethod
    def get_role_by_name(cls, name):
        """Get a role by its name"""
        roles = cls.get_all_roles()
        for role in roles:
            if role.name == name:
                return role
        return None
    
    @classmethod
    def create_role(cls, name, description=None, tag_access=None):
        """Create a new role and save to JSON file"""
        # Check if role with this name already exists
        if cls.get_role_by_name(name):
            return None
        
        # Create new role
        role = cls(name=name, description=description, tag_access=tag_access)
        
        # Save to file
        roles = cls.get_all_roles()
        roles.append(role)
        cls._save_roles(roles)
        
        return role
    
    @classmethod
    def update_role(cls, role_id, **kwargs):
        """Update role attributes"""
        role = cls.get_role_by_id(role_id)
        if not role:
            return False
        
        # Update attributes
        for key, value in kwargs.items():
            if hasattr(role, key):
                setattr(role, key, value)
        
        # Save changes
        roles = cls.get_all_roles()
        for i, existing_role in enumerate(roles):
            if existing_role.id == role_id:
                roles[i] = role
                break
        
        cls._save_roles(roles)
        return True
    
    @classmethod
    def delete_role(cls, role_id):
        """Delete a role"""
        # Don't allow deletion if users are assigned to this role
        users = User.get_all_users()
        for user in users:
            if user.role_id == role_id:
                return False  # Role is in use
        
        roles = cls.get_all_roles()
        roles = [role for role in roles if role.id != role_id]
        cls._save_roles(roles)
        return True
    
    @classmethod
    def _save_roles(cls, roles):
        """Save roles list to JSON file"""
        # Ensure directory exists
        os.makedirs(os.path.dirname(cls.ROLES_FILE), exist_ok=True)
        
        # Save to file
        with open(cls.ROLES_FILE, 'w') as f:
            json.dump([role.to_dict() for role in roles], f, indent=2)
    
    def has_access_to_tag(self, tag_id):
        """Check if this role has access to a specific tag"""
        return tag_id in self.tag_access 