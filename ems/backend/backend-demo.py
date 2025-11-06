# backend-demo.py

# COMMENT: Initialization
# This section imports the necessary libraries and initializes the Flask application and its extensions.
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from flask_socketio import SocketIO, emit

app = Flask(__name__)
# Configuration for the application is loaded from a separate class.
# app.config.from_object(Config)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
socketio = SocketIO(app)

# COMMENT: Models
# These are SQLAlchemy models that represent the database tables.

class User(db.Model):
    """
    Represents a user in the system.
    """
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(50), nullable=False)

    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

class Incident(db.Model):
    """
    Represents an emergency incident.
    """
    __tablename__ = 'incidents'
    incident_id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.patient_id'), nullable=False)
    dispatcher_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=True)
    ambulance_id = db.Column(db.Integer, db.ForeignKey('ambulances.ambulance_id'), nullable=True)
    destination_hospital_id = db.Column(db.Integer, db.ForeignKey('hospitals.hospital_id'), nullable=True)
    status = db.Column(db.String(50), nullable=False, default='active')

# COMMENT: Authentication
# This section handles user login and token generation.

@app.route('/api/login', methods=['POST'])
def login_user():
    """
    Authenticates a user and returns a JWT access token.
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        access_token = create_access_token(identity=str(user.user_id))
        return jsonify(access_token=access_token)
    else:
        return jsonify(error="Invalid credentials"), 401

# COMMENT: API Endpoints
# These are the main API routes for interacting with the application.

@app.route('/api/ambulances', methods=['GET'])
@jwt_required()
def get_ambulances_route():
    """
    Returns a list of all ambulances.
    """
    # In a real application, you would query the database for ambulances.
    # ambulances = Ambulance.query.all()
    # return jsonify([amb.to_dict() for amb in ambulances])
    return jsonify([{'id': 1, 'license_plate': 'AMB-001', 'status': 'available'}])

@app.route('/api/incidents', methods=['POST'])
@jwt_required()
def post_incident_route():
    """
    Creates a new incident.
    """
    data = request.get_json()
    # In a real application, you would create a new Incident model instance and save it to the database.
    # new_incident = Incident(**data)
    # db.session.add(new_incident)
    # db.session.commit()
    return jsonify(data), 201

# COMMENT: WebSocket Events
# This section handles real-time communication with the frontend.

@socketio.on('connect')
def handle_connect():
    """
    Handles a new WebSocket connection.
    """
    print('Client connected')
    emit('connection_response', {'data': 'Connected'})

@socketio.on('join_incident_room')
def handle_join_incident_room(data):
    """
    Joins a client to a room for a specific incident.
    """
    incident_id = data.get('incident_id')
    # In a real application, you would use rooms to send updates to specific clients.
    # join_room(f'incident_{incident_id}')
    print(f"Client joined room for incident {incident_id}")

# COMMENT: Main Entry Point
# This is the main entry point for the application.

if __name__ == '__main__':
    # In a real application, you would create the database tables if they don't exist.
    # with app.app_context():
    #     db.create_all()
    socketio.run(app, debug=True)

