"""
User management for Vehicle Passport Blockchain
Handles users, roles, keypairs, and permissions
"""

from crypto_utils import generate_keypair, sign_transaction, verify_transaction_signature


class User:
    """Represents a user in the system with role and keypair"""
    
    def __init__(self, user_id, role, private_key, public_key):
        self.user_id = user_id
        self.role = role
        self.private_key = private_key
        self.public_key = public_key
    
    def to_dict(self):
        """Convert user to dictionary (excluding private key for safety)"""
        return {
            'user_id': self.user_id,
            'role': self.role,
            'public_key': self.public_key
        }


# Role definitions and permissions
ROLES = {
    'MANUFACTURER': ['VEHICLE_CREATED', 'OWNERSHIP_TRANSFER'],
    'DMV': ['VEHICLE_CREATED', 'OWNERSHIP_TRANSFER'],
    'MECHANIC': ['MILEAGE_UPDATE', 'SERVICE_RECORD'],
    'INSURER': ['ACCIDENT_RECORD'],
    'BUYER': []  # Read-only
}


# Global user registry
USERS = {}


def initialize_users():
    """
    Initialize the system with a predefined set of users
    Generates keypairs for each user at startup
    """
    global USERS
    
    user_configs = [
        # Manufacturers
        ('manufacturer_1', 'MANUFACTURER'),
        ('manufacturer_2', 'MANUFACTURER'),
        
        # DMV offices
        ('dmv_1', 'DMV'),
        ('dmv_2', 'DMV'),
        
        # Mechanics
        ('mechanic_1', 'MECHANIC'),
        ('mechanic_2', 'MECHANIC'),
        ('mechanic_3', 'MECHANIC'),
        
        # Insurers
        ('insurer_1', 'INSURER'),
        ('insurer_2', 'INSURER'),
        
        # Buyers/Owners
        ('buyer_1', 'BUYER'),
        ('buyer_2', 'BUYER'),
        ('buyer_3', 'BUYER'),
    ]
    
    for user_id, role in user_configs:
        private_key, public_key = generate_keypair()
        user = User(user_id, role, private_key, public_key)
        USERS[user_id] = user
    
    return USERS


def get_user(user_id):
    """
    Get a user by ID
    
    Args:
        user_id: User identifier
    
    Returns:
        User object or None if not found
    """
    return USERS.get(user_id)


def get_users_by_role(role):
    """
    Get all users with a specific role
    
    Args:
        role: Role name (MANUFACTURER, DMV, MECHANIC, INSURER, BUYER)
    
    Returns:
        List of User objects
    """
    return [user for user in USERS.values() if user.role == role]


def get_all_users():
    """
    Get all users in the system
    
    Returns:
        Dictionary of user_id -> User object
    """
    return USERS


def can_user_create_transaction(user_id, transaction_type):
    """
    Check if a user has permission to create a specific transaction type
    
    Args:
        user_id: User identifier
        transaction_type: Transaction type (e.g., 'VEHICLE_CREATED')
    
    Returns:
        bool: True if user can create this transaction type
    """
    user = get_user(user_id)
    if not user:
        return False
    
    allowed_types = ROLES.get(user.role, [])
    return transaction_type in allowed_types


def create_and_sign_transaction(user_id, vin, tx_type, payload):
    """
    Create and sign a transaction for a user
    Combines transaction creation with signing and permission checking
    
    Args:
        user_id: User creating the transaction
        vin: Vehicle identification number
        tx_type: Transaction type
        payload: Transaction payload (dict)
    
    Returns:
        Transaction object (signed) or None if permission denied
    """
    from blockchain import Transaction
    
    user = get_user(user_id)
    if not user:
        raise ValueError(f"User {user_id} not found")
    
    # Check permissions
    if not can_user_create_transaction(user_id, tx_type):
        raise PermissionError(
            f"User {user_id} with role {user.role} cannot create {tx_type} transactions"
        )
    
    # Create transaction
    transaction = Transaction(
        vin=vin,
        tx_type=tx_type,
        actor_id=user_id,
        role=user.role,
        payload=payload
    )
    
    # Sign transaction
    sign_transaction(transaction, user.private_key)
    
    return transaction


def verify_transaction(transaction):
    """
    Verify a transaction's signature and permissions
    
    Args:
        transaction: Transaction object
    
    Returns:
        bool: True if transaction is valid (signature + permissions)
    """
    # Get user
    user = get_user(transaction.actor_id)
    if not user:
        return False
    
    # Verify signature
    if not verify_transaction_signature(transaction, user.public_key):
        return False
    
    # Verify permissions
    if not can_user_create_transaction(transaction.actor_id, transaction.type):
        return False
    
    return True