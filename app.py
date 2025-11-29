from flask import Flask, render_template, session, request, jsonify
from argparse import ArgumentParser
from blockchain import Blockchain, Transaction
from users import initialize_users, get_user, get_users_by_role, create_and_sign_transaction, verify_transaction
import secrets

# ========== INITIALIZE FLASK APP ==========
app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# ========== INITIALIZE GLOBAL BLOCKCHAIN & USERS ==========
blockchain = Blockchain()
users = initialize_users()

# ========== ROLE CONFIGURATION ==========
ROLE_PERMISSIONS = {
    'MANUFACTURER': ['VEHICLE_CREATED', 'OWNERSHIP_TRANSFER'],
    'DMV': ['VEHICLE_CREATED', 'OWNERSHIP_TRANSFER'],
    'MECHANIC': ['MILEAGE_UPDATE', 'SERVICE_RECORD'],
    'INSURER': ['ACCIDENT_RECORD'],
    'BUYER': []
}

AVAILABLE_ROLES = list(ROLE_PERMISSIONS.keys())


# ========== HTML ROUTES ==========

@app.route('/')
def index():
    """Home page / dashboard"""
    return render_template('index.html')

@app.route('/home')
def home():
    """Alias for home page"""
    return render_template('index.html')

@app.route('/vehicles/register')
def vehicle_register():
    return render_template('vehicle_register.html')

@app.route('/vehicles/mileage')
def vehicle_mileage():
    return render_template('vehicle_mileage.html')

@app.route('/vehicles/service')
def vehicle_service():
    return render_template('vehicle_service.html')

@app.route('/vehicles/accident')
def vehicle_accident():
    return render_template('vehicle_accident.html')

@app.route('/vehicles/transfer')
def vehicle_transfer():
    return render_template('vehicle_transfer.html')

@app.route('/vehicles/')
@app.route('/vehicles/<vin>')
def vehicle_detail(vin=None):
    return render_template('vehicle_detail.html')

@app.route('/chain')
def chain_explorer():
    return render_template('chain.html')

@app.route('/validate')
def validate_chain():
    return render_template('validate.html')


# ========== API ROUTES ==========

@app.route('/api/roles', methods=['GET'])
def api_get_roles():
    """Get all available roles"""
    return jsonify({'roles': AVAILABLE_ROLES})

@app.route('/api/users/<role>', methods=['GET'])
def api_get_users_by_role(role):
    """Get users for a specific role"""
    role_users = get_users_by_role(role)
    return jsonify({
        'users': [{'user_id': u.user_id, 'role': u.role} for u in role_users]
    })

@app.route('/api/session/set', methods=['POST'])
def api_set_session():
    """Set current role and user in session"""
    data = request.get_json()
    session['role'] = data.get('role')
    session['user_id'] = data.get('user_id')
    return jsonify({'success': True})

@app.route('/api/session/get', methods=['GET'])
def api_get_session():
    """Get current session data"""
    return jsonify({
        'role': session.get('role'),
        'user_id': session.get('user_id')
    })

@app.route('/api/session/clear', methods=['POST'])
def api_clear_session():
    """Clear session"""
    session.clear()
    return jsonify({'success': True})

@app.route('/api/stats', methods=['GET'])
def api_get_stats():
    """Get blockchain statistics"""
    return jsonify({
        'total_blocks': len(blockchain.chain),
        'total_vehicles': len(blockchain.vin_index),
        'pending_transactions': len(blockchain.transactions),
        'chain_valid': blockchain.is_chain_valid()
    })

@app.route('/api/chain', methods=['GET'])
def api_get_chain():
    """Get the entire blockchain"""
    return jsonify({
        'chain': blockchain.get_chain_data(),
        'length': len(blockchain.chain)
    })

@app.route('/api/vehicle/<vin>', methods=['GET'])
def api_get_vehicle(vin):
    """Get vehicle information and history"""
    if not blockchain.vehicle_exists(vin):
        return jsonify({'error': 'Vehicle not found'}), 404
    
    info = blockchain.get_vehicle_info(vin)
    history = blockchain.get_vehicle_history(vin)
    
    return jsonify({
        'info': info,
        'history': [tx.to_dict() for tx in history]
    })

@app.route('/api/vehicle/register', methods=['POST'])
def api_register_vehicle():
    """Register a new vehicle"""
    data = request.get_json()
    user_id = session.get('user_id')
    
    if not user_id:
        return jsonify({'error': 'Not logged in'}), 401
    
    try:
        # Create and sign transaction
        transaction = create_and_sign_transaction(
            user_id=user_id,
            vin=data['vin'],
            tx_type='VEHICLE_CREATED',
            payload={
                'make': data['make'],
                'model': data['model'],
                'year': int(data['year']),
                'initial_mileage': int(data['initial_mileage']),
                'owner_id': data.get('owner_id', user_id)
            }
        )
        
        # Add to blockchain
        blockchain.add_transaction(transaction)
        last_block = blockchain.get_last_block()
        blockchain.create_block(nonce=1, previous_hash=last_block.hash)
        
        return jsonify({'success': True, 'vin': data['vin']})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/vehicle/mileage', methods=['POST'])
def api_update_mileage():
    """Update vehicle mileage"""
    data = request.get_json()
    user_id = session.get('user_id')
    
    if not user_id:
        return jsonify({'error': 'Not logged in'}), 401
    
    vin = data['vin']
    new_mileage = int(data['new_mileage'])
    
    # Check mileage validity
    last_mileage = blockchain.get_latest_mileage(vin)
    if last_mileage and new_mileage < last_mileage:
        return jsonify({'error': f'New mileage ({new_mileage}) cannot be less than last recorded mileage ({last_mileage})'}), 400
    
    try:
        transaction = create_and_sign_transaction(
            user_id=user_id,
            vin=vin,
            tx_type='MILEAGE_UPDATE',
            payload={
                'new_mileage': new_mileage,
                'description': data.get('description', '')
            }
        )
        
        blockchain.add_transaction(transaction)
        last_block = blockchain.get_last_block()
        blockchain.create_block(nonce=1, previous_hash=last_block.hash)
        
        return jsonify({'success': True})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/vehicle/service', methods=['POST'])
def api_add_service():
    """Add service record"""
    data = request.get_json()
    user_id = session.get('user_id')
    
    if not user_id:
        return jsonify({'error': 'Not logged in'}), 401
    
    try:
        transaction = create_and_sign_transaction(
            user_id=user_id,
            vin=data['vin'],
            tx_type='SERVICE_RECORD',
            payload={
                'service_type': data['service_type'],
                'description': data.get('description', '')
            }
        )
        
        blockchain.add_transaction(transaction)
        last_block = blockchain.get_last_block()
        blockchain.create_block(nonce=1, previous_hash=last_block.hash)
        
        return jsonify({'success': True})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/vehicle/accident', methods=['POST'])
def api_add_accident():
    """Add accident record"""
    data = request.get_json()
    user_id = session.get('user_id')
    
    if not user_id:
        return jsonify({'error': 'Not logged in'}), 401
    
    try:
        transaction = create_and_sign_transaction(
            user_id=user_id,
            vin=data['vin'],
            tx_type='ACCIDENT_RECORD',
            payload={
                'severity': data['severity'],
                'description': data.get('description', '')
            }
        )
        
        blockchain.add_transaction(transaction)
        last_block = blockchain.get_last_block()
        blockchain.create_block(nonce=1, previous_hash=last_block.hash)
        
        return jsonify({'success': True})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/vehicle/transfer', methods=['POST'])
def api_transfer_ownership():
    """Transfer vehicle ownership"""
    data = request.get_json()
    user_id = session.get('user_id')
    
    if not user_id:
        return jsonify({'error': 'Not logged in'}), 401
    
    try:
        transaction = create_and_sign_transaction(
            user_id=user_id,
            vin=data['vin'],
            tx_type='OWNERSHIP_TRANSFER',
            payload={
                'new_owner_id': data['new_owner_id']
            }
        )
        
        blockchain.add_transaction(transaction)
        last_block = blockchain.get_last_block()
        blockchain.create_block(nonce=1, previous_hash=last_block.hash)
        
        return jsonify({'success': True})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/validate', methods=['GET'])
def api_validate_chain():
    """Validate blockchain integrity"""
    is_valid = blockchain.is_chain_valid()
    return jsonify({
        'valid': is_valid,
        'total_blocks': len(blockchain.chain)
    })


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5001, type=int, help="port to listen to")
    args = parser.parse_args()
    port = args.port
    
    print("\n" + "=" * 60)
    print("STARTING VEHICLE PASSPORT BLOCKCHAIN APPLICATION")
    print("=" * 60)
    print(f"Server running on http://127.0.0.1:{port}")
    print("=" * 60 + "\n")
    
    app.run(host='127.0.0.1', port=port, debug=True)