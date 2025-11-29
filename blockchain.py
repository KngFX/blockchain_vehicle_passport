from time import time
import json
import hashlib
from collections import defaultdict


class Transaction:
    """
    Represents a vehicle passport transaction.
    Types: VEHICLE_CREATED, MILEAGE_UPDATE, SERVICE_RECORD, ACCIDENT_RECORD, OWNERSHIP_TRANSFER
    
    This is primarily a data object. Signing is handled externally via crypto_utils or users.py
    """
    
    def __init__(self, vin, tx_type, actor_id, role, payload):
        self.vin = vin
        self.type = tx_type
        self.actor_id = actor_id
        self.role = role
        self.timestamp = time()
        self.payload = payload
        self.tx_id = None
        self.signature = None
        
        # Compute transaction ID
        self.tx_id = self._compute_tx_id()
    
    def to_dict(self):
        """Convert transaction to dictionary"""
        return {
            'tx_id': self.tx_id,
            'vin': self.vin,
            'type': self.type,
            'actor_id': self.actor_id,
            'role': self.role,
            'timestamp': self.timestamp,
            'payload': self.payload,
            'signature': self.signature
        }
    
    def _compute_tx_id(self):
        """Compute SHA256 hash of transaction data (without signature)"""
        tx_data = {
            'vin': self.vin,
            'type': self.type,
            'actor_id': self.actor_id,
            'role': self.role,
            'timestamp': self.timestamp,
            'payload': self.payload
        }
        tx_string = json.dumps(tx_data, sort_keys=True).encode('utf8')
        h = hashlib.sha256()
        h.update(tx_string)
        return h.hexdigest()
    
    @classmethod
    def from_dict(cls, tx_dict):
        """Create Transaction object from dictionary"""
        tx = cls(
            vin=tx_dict['vin'],
            tx_type=tx_dict['type'],
            actor_id=tx_dict['actor_id'],
            role=tx_dict['role'],
            payload=tx_dict['payload']
        )
        tx.timestamp = tx_dict['timestamp']
        tx.tx_id = tx_dict.get('tx_id')
        tx.signature = tx_dict.get('signature')
        return tx


class Block:
    """
    Represents a block in the vehicle passport blockchain
    """
    
    def __init__(self, block_number, transactions, previous_hash, nonce=0):
        self.block_number = block_number
        self.timestamp = time()
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = None
    
    def compute_hash(self):
        """Compute SHA256 hash of the block"""
        block_dict = {
            'block_number': self.block_number,
            'timestamp': self.timestamp,
            'transactions': [tx.to_dict() for tx in self.transactions],
            'nonce': self.nonce,
            'previous_hash': self.previous_hash
        }
        block_string = json.dumps(block_dict, sort_keys=True).encode('utf8')
        h = hashlib.sha256()
        h.update(block_string)
        return h.hexdigest()
    
    def to_dict(self):
        """Convert block to dictionary"""
        return {
            'block_number': self.block_number,
            'timestamp': self.timestamp,
            'transactions': [tx.to_dict() for tx in self.transactions],
            'nonce': self.nonce,
            'previous_hash': self.previous_hash,
            'hash': self.hash
        }


class Blockchain:
    """
    Vehicle Passport Blockchain
    Manages the chain of blocks and transaction validation
    Includes VIN indexing for fast vehicle history lookups
    """
    
    def __init__(self):
        self.chain = []
        self.transactions = []
        
        # VIN Index: dict mapping VIN -> list of transactions
        self.vin_index = defaultdict(list)
        
        # Create genesis block
        self.create_block(nonce=0, previous_hash='00')
    
    def create_block(self, nonce, previous_hash):
        """
        Add a block of transactions to the blockchain
        Also updates the VIN index
        """
        block = Block(
            block_number=len(self.chain) + 1,
            transactions=self.transactions,
            previous_hash=previous_hash,
            nonce=nonce
        )
        
        # Compute and set block hash
        block.hash = block.compute_hash()
        
        # Index all transactions in this block
        self._index_block(block)
        
        # Reset the current list of transactions
        self.transactions = []
        
        # Add block to chain
        self.chain.append(block)
        
        return block
    
    def add_transaction(self, transaction):
        """
        Add a transaction to the list of pending transactions
        """
        self.transactions.append(transaction)
        return len(self.chain) + 1
    
    def get_last_block(self):
        """Get the last block in the chain"""
        return self.chain[-1]
    
    def is_chain_valid(self):
        """
        Check if the blockchain is valid
        Verifies:
        1. Block hashes are correct
        2. Block links are correct (previous_hash matches)
        """
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            
            # Check if the hash of the block is correct
            if current_block.hash != current_block.compute_hash():
                print(f"Block {i} hash is invalid")
                return False
            
            # Check if previous_hash matches the hash of the previous block
            if current_block.previous_hash != previous_block.hash:
                print(f"Block {i} previous_hash doesn't match")
                return False
        
        return True
    
    def get_chain_data(self):
        """Get the entire blockchain as a list of dictionaries"""
        return [block.to_dict() for block in self.chain]
    
    # ========== VIN INDEX METHODS ==========
    
    def _index_transaction(self, transaction):
        """
        Add a transaction to the VIN index
        
        Args:
            transaction: Transaction object to index
        """
        self.vin_index[transaction.vin].append(transaction)
    
    def _index_block(self, block):
        """
        Index all transactions in a block
        Called automatically when a block is created
        
        Args:
            block: Block object containing transactions
        """
        for transaction in block.transactions:
            self._index_transaction(transaction)
    
    def get_vehicle_history(self, vin):
        """
        Get all transactions for a specific VIN, sorted by timestamp
        Uses the VIN index for O(1) lookup
        
        Args:
            vin: Vehicle identification number
        
        Returns:
            List of Transaction objects, sorted chronologically
        """
        transactions = self.vin_index.get(vin, [])
        return sorted(transactions, key=lambda tx: tx.timestamp)
    
    def get_vehicle_info(self, vin):
        """
        Get comprehensive vehicle information from its history
        
        Args:
            vin: Vehicle identification number
        
        Returns:
            dict with vehicle details, or None if VIN not found
        """
        history = self.get_vehicle_history(vin)
        
        if not history:
            return None
        
        info = {
            'vin': vin,
            'make': None,
            'model': None,
            'year': None,
            'current_owner': None,
            'latest_mileage': None,
            'created_by': None,
            'created_at': None,
            'total_transactions': len(history)
        }
        
        # Extract information from transaction history
        for tx in history:
            if tx.type == 'VEHICLE_CREATED':
                info['make'] = tx.payload.get('make')
                info['model'] = tx.payload.get('model')
                info['year'] = tx.payload.get('year')
                info['latest_mileage'] = tx.payload.get('initial_mileage')
                info['current_owner'] = tx.payload.get('owner_id', tx.actor_id)
                info['created_by'] = tx.actor_id
                info['created_at'] = tx.timestamp
            
            elif tx.type == 'MILEAGE_UPDATE':
                info['latest_mileage'] = tx.payload.get('new_mileage')
            
            elif tx.type == 'OWNERSHIP_TRANSFER':
                info['current_owner'] = tx.payload.get('new_owner_id')
        
        return info
    
    def get_latest_mileage(self, vin):
        """
        Get the most recent mileage for a vehicle
        
        Args:
            vin: Vehicle identification number
        
        Returns:
            int: Latest mileage, or None if no mileage records exist
        """
        history = self.get_vehicle_history(vin)
        
        mileage = None
        
        for tx in history:
            if tx.type == 'VEHICLE_CREATED' and 'initial_mileage' in tx.payload:
                mileage = tx.payload['initial_mileage']
            elif tx.type == 'MILEAGE_UPDATE' and 'new_mileage' in tx.payload:
                mileage = tx.payload['new_mileage']
        
        return mileage
    
    def vehicle_exists(self, vin):
        """
        Check if a vehicle exists in the blockchain
        
        Args:
            vin: Vehicle identification number
        
        Returns:
            bool: True if vehicle has been registered
        """
        return vin in self.vin_index and len(self.vin_index[vin]) > 0
    
    def rebuild_index_from_chain(self):
        """
        Rebuild the VIN index from scratch by scanning the entire chain
        Useful for testing or recovering from index corruption
        """
        self.vin_index = defaultdict(list)
        
        for block in self.chain:
            self._index_block(block)
        
        return len(self.vin_index)