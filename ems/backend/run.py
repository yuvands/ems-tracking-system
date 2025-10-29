from flask import Flask, jsonify, request, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import joinedload, validates # For eager loading and validation
from sqlalchemy import func, event # For database functions like now() and event listeners
from config import Config
import datetime
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    create_access_token, jwt_required, JWTManager,
    get_jwt_identity, get_jwt, verify_jwt_in_request
)
from functools import wraps # For custom decorators
import re # For basic validation
import math # For distance calculation
import logging # For logging

# --- Import SocketIO ---
from flask_socketio import SocketIO, emit, join_room, leave_room

# --- Basic Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

app = Flask(__name__)
app.config.from_object(Config)
app.config["JWT_SECRET_KEY"] = Config.SECRET_KEY or "change-this-super-secret-key-in-prod-ASAP!" # CHANGE THIS!
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = datetime.timedelta(hours=8)

db = SQLAlchemy(app)
# Allow all origins for dev, be more specific in production
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
# --- Initialize SocketIO ---
# Use eventlet for async mode, recommended for production
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')


# --- Role Definition & Validation Constants ---
ROLES = { 'SUPERVISOR': 'supervisor', 'DISPATCHER': 'dispatcher', 'PARAMEDIC': 'paramedic', 'HOSPITAL_STAFF': 'hospital_staff' }
VALID_ROLES = set(ROLES.values())
VALID_AMBULANCE_STATUSES = {'available', 'en_route_to_scene', 'at_scene', 'en_route_to_hospital', 'unavailable', 'maintenance_required'}
VALID_INCIDENT_STATUSES = {'active', 'en_route_to_scene', 'at_scene', 'en_route_to_hospital', 'closed', 'cancelled'}
VALID_EQUIPMENT_STATUSES = {'operational', 'maintenance_required'}

# --- Custom Decorator for Role Checks ---
def roles_required(*required_roles):
    def decorator(fn):
        @wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            claims = get_jwt()
            user_role = claims.get("role", None)
            if user_role not in required_roles:
                return jsonify(error=f"Unauthorized: Roles required: {', '.join(required_roles)}"), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


## -- Models (with Relationships & Basic Validation) -- ##
# (Models remain unchanged - code omitted for brevity)
class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    hospital_id = db.Column(db.Integer, db.ForeignKey('hospitals.hospital_id'), nullable=True) # Link to hospital for staff
    staff_profile = db.relationship('Staff', back_populates='user', uselist=False, cascade="all, delete-orphan")
    # hospital relationship available via backref 'staff_users' from Hospital model

    @validates('role')
    def validate_role(self, key, role):
        if role not in VALID_ROLES: raise ValueError(f"Invalid role. Must be one of: {', '.join(VALID_ROLES)}")
        return role

    @validates('username')
    def validate_username(self, key, username):
        if not re.match("^[a-zA-Z0-9_]{3,20}$", username): raise ValueError("Username invalid.")
        return username.lower()

    def set_password(self, password):
        if len(password) < 8: raise ValueError("Password too short.")
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

    def to_dict(self):
        return { 'id': self.user_id, 'username': self.username, 'full_name': self.full_name, 'role': self.role, 'hospital_id': self.hospital_id }

class Staff(db.Model):
    __tablename__ = 'staff'
    staff_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False, unique=True)
    certification_level = db.Column(db.String(50), nullable=True)
    assigned_ambulance_id = db.Column(db.Integer, db.ForeignKey('ambulances.ambulance_id'), nullable=True)
    user = db.relationship('User', back_populates='staff_profile', lazy='joined')
    ambulance = db.relationship('Ambulance', backref=db.backref('staff_assigned', lazy='dynamic'))

    def to_dict(self):
        user_info = self.user.to_dict() if self.user else {}
        return { 'staff_id': self.staff_id, 'user_id': self.user_id, 'full_name': user_info.get('full_name'), 'certification_level': self.certification_level, 'assigned_ambulance_id': self.assigned_ambulance_id }

class Ambulance(db.Model):
    __tablename__ = 'ambulances'
    ambulance_id = db.Column(db.Integer, primary_key=True)
    license_plate = db.Column(db.String(20), unique=True, nullable=False)
    status = db.Column(db.String(50), nullable=False, default='available')
    current_lat = db.Column(db.DECIMAL(10, 8), nullable=True)
    current_lon = db.Column(db.DECIMAL(11, 8), nullable=True)
    equipment = db.relationship('Equipment', backref='ambulance', lazy='dynamic', cascade="all, delete-orphan")
    # staff_assigned available via backref

    @validates('status')
    def validate_status(self, key, status):
        if status not in VALID_AMBULANCE_STATUSES: raise ValueError(f"Invalid ambulance status.")
        return status

    def to_dict(self):
        return { 'id': self.ambulance_id, 'license_plate': self.license_plate, 'status': self.status, 'latitude': str(self.current_lat) if self.current_lat is not None else None, 'longitude': str(self.current_lon) if self.current_lon is not None else None }

# --- Event listener for Ambulance ---
@event.listens_for(Ambulance, 'after_update')
def receive_after_update(mapper, connection, target):
    logging.info(f"Ambulance {target.ambulance_id} updated. Emitting update.")
    socketio.emit('ambulance_update', target.to_dict(), room='dashboard_updates')

class Equipment(db.Model):
    __tablename__ = 'equipment'
    equipment_id = db.Column(db.Integer, primary_key=True)
    ambulance_id = db.Column(db.Integer, db.ForeignKey('ambulances.ambulance_id'), nullable=False)
    equipment_name = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(50), nullable=False, default='operational')

    @validates('status')
    def validate_status(self, key, status):
        if status not in VALID_EQUIPMENT_STATUSES: raise ValueError(f"Invalid equipment status.")
        return status

    def to_dict(self):
        return { 'equipment_id': self.equipment_id, 'ambulance_id': self.ambulance_id, 'equipment_name': self.equipment_name, 'status': self.status }

class Hospital(db.Model):
    __tablename__ = 'hospitals'
    hospital_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(255), nullable=True)
    latitude = db.Column(db.DECIMAL(10, 8), nullable=False)
    longitude = db.Column(db.DECIMAL(11, 8), nullable=False)
    er_capacity = db.Column(db.Integer, nullable=True)
    er_current_occupancy = db.Column(db.Integer, nullable=True, default=0)
    specialties = db.relationship('HospitalSpecialties', backref='hospital', lazy='dynamic', cascade="all, delete-orphan")
    staff_users = db.relationship('User', backref='assigned_hospital', lazy='dynamic')

    @validates('er_capacity', 'er_current_occupancy')
    def validate_capacity(self, key, value):
        if value is not None and value < 0: raise ValueError(f"{key} cannot be negative.")
        return value

    def to_dict(self):
        return { 'id': self.hospital_id, 'name': self.name, 'address': self.address, 'latitude': str(self.latitude) if self.latitude is not None else None, 'longitude': str(self.longitude) if self.longitude is not None else None, 'er_capacity': self.er_capacity, 'er_current_occupancy': self.er_current_occupancy }

class HospitalSpecialties(db.Model):
    __tablename__ = 'hospital_specialties'
    specialty_id = db.Column(db.Integer, primary_key=True)
    hospital_id = db.Column(db.Integer, db.ForeignKey('hospitals.hospital_id'), nullable=False)
    specialty_name = db.Column(db.String(100), nullable=False)
    is_available = db.Column(db.Boolean, default=True)

    def to_dict(self):
        return { 'specialty_id': self.specialty_id, 'hospital_id': self.hospital_id, 'specialty_name': self.specialty_name, 'is_available': self.is_available }

class Patient(db.Model):
    __tablename__ = 'patients'
    patient_id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=True)
    dob = db.Column(db.Date, nullable=True)
    blood_type = db.Column(db.String(5), nullable=True)
    incidents = db.relationship('Incident', backref='patient', lazy='dynamic')

    def to_dict(self):
        return { 'id': self.patient_id, 'full_name': self.full_name, 'dob': str(self.dob) if self.dob else None, 'blood_type': self.blood_type }

class Incident(db.Model):
    __tablename__ = 'incidents'
    incident_id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.patient_id'), nullable=False)
    dispatcher_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=True)
    ambulance_id = db.Column(db.Integer, db.ForeignKey('ambulances.ambulance_id'), nullable=True)
    destination_hospital_id = db.Column(db.Integer, db.ForeignKey('hospitals.hospital_id'), nullable=True)
    location_lat = db.Column(db.DECIMAL(10, 8), nullable=False)
    location_lon = db.Column(db.DECIMAL(11, 8), nullable=False)
    location_description = db.Column(db.Text, nullable=True)
    incident_time = db.Column(db.TIMESTAMP, server_default=func.now())
    status = db.Column(db.String(50), nullable=False, default='active')
    vitals_logs = db.relationship('PatientVitalsLog', backref='incident', lazy='dynamic', cascade="all, delete-orphan")
    dispatcher = db.relationship('User', lazy='joined')
    ambulance = db.relationship('Ambulance', lazy='joined')
    destination_hospital = db.relationship('Hospital', lazy='joined')
    # patient relationship via backref

    @validates('status')
    def validate_status(self, key, status):
        if status not in VALID_INCIDENT_STATUSES: raise ValueError(f"Invalid incident status.")
        return status

    def to_dict(self, include_details=True):
        data = { 'id': self.incident_id, 'patient_id': self.patient_id, 'dispatcher_id': self.dispatcher_id, 'ambulance_id': self.ambulance_id, 'destination_hospital_id': self.destination_hospital_id, 'latitude': str(self.location_lat) if self.location_lat is not None else None, 'longitude': str(self.location_lon) if self.location_lon is not None else None, 'description': self.location_description, 'incident_time': self.incident_time.isoformat() if self.incident_time else None, 'status': self.status }
        if include_details:
            data['patient'] = self.patient.to_dict() if self.patient else None
            data['ambulance_plate'] = self.ambulance.license_plate if self.ambulance else None
            data['hospital_name'] = self.destination_hospital.name if self.destination_hospital else None
            data['dispatcher_name'] = self.dispatcher.full_name if self.dispatcher else None
        return data

# --- Event listener for Incident status changes ---
@event.listens_for(Incident.status, 'set')
def receive_set_incident(target, value, oldvalue, initiator):
    if oldvalue != value and hasattr(target, 'incident_id') and target.incident_id is not None:
        if 'pending_emissions' not in session: session['pending_emissions'] = []
        incident_full = Incident.query.options(
            joinedload(Incident.patient), joinedload(Incident.ambulance),
            joinedload(Incident.destination_hospital), joinedload(Incident.dispatcher)
        ).get(target.incident_id)
        if incident_full:
             session['pending_emissions'].append(('incident_update', incident_full.to_dict(include_details=True)))
             logging.info(f"Incident {target.incident_id} status changed to {value}. Queued emission.")
        else:
             logging.warning(f"Could not refetch incident {target.incident_id} for emission.")

# --- Listener for after commit ---
@event.listens_for(db.session, 'after_commit')
def after_commit(session_instance):
    if 'pending_emissions' in session:
        for event_name, data in session['pending_emissions']:
            logging.info(f"Emitting {event_name} for ID {data.get('id')}")
            socketio.emit(event_name, data, room='dashboard_updates')
        del session['pending_emissions']

class PatientVitalsLog(db.Model):
    __tablename__ = 'patient_vitals_log'
    log_id = db.Column(db.BigInteger, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey('incidents.incident_id'), nullable=False)
    timestamp = db.Column(db.TIMESTAMP, server_default=func.now())
    heart_rate = db.Column(db.Integer, nullable=True)
    blood_pressure_systolic = db.Column(db.Integer, nullable=True)
    blood_pressure_diastolic = db.Column(db.Integer, nullable=True)
    oxygen_saturation = db.Column(db.DECIMAL(5, 2), nullable=True)

    def to_dict(self):
        return { 'log_id': self.log_id, 'incident_id': self.incident_id, 'timestamp': self.timestamp.isoformat() if self.timestamp else None, 'heart_rate': self.heart_rate, 'blood_pressure_systolic': self.blood_pressure_systolic, 'blood_pressure_diastolic': self.blood_pressure_diastolic, 'oxygen_saturation': str(self.oxygen_saturation) if self.oxygen_saturation is not None else None }


## -- Authentication API Routes -- ##
@app.route('/api/register', methods=['POST'])
def register_user():
    data = request.get_json();
    if not data: return jsonify(error="Missing JSON body"), 400;
    username = data.get('username'); password = data.get('password'); full_name = data.get('full_name'); role = data.get('role'); hospital_id = data.get('hospital_id');
    if not username or not password or not full_name or not role: return jsonify(error="Missing required fields"), 400;
    if User.query.filter(func.lower(User.username) == username.lower()).first(): return jsonify(error="Username exists"), 409;
    try:
        new_user = User(username=username, full_name=full_name, role=role); new_user.set_password(password);
        if role == ROLES['HOSPITAL_STAFF']:
            if not hospital_id: return jsonify(error="hospital_id required for role"), 400;
            hospital = Hospital.query.get(hospital_id);
            if not hospital: return jsonify(error=f"Hospital ID {hospital_id} not found"), 404;
            new_user.hospital_id = hospital_id;
        db.session.add(new_user); db.session.commit();
        return jsonify(new_user.to_dict()), 201;
    except ValueError as ve: db.session.rollback(); return jsonify(error=str(ve)), 400;
    except Exception as e: db.session.rollback(); app.logger.error(f"Reg err: {e}"); return jsonify(error="Internal error"), 500

@app.route('/api/login', methods=['POST'])
def login_user():
    data = request.get_json();
    if not data: return jsonify(error="Missing body"), 400;
    username = data.get('username'); password = data.get('password');
    if not username or not password: return jsonify(error="Missing credentials"), 400;
    user = User.query.filter(func.lower(User.username) == username.lower()).first();
    if user and user.check_password(password):
        claims = {"role": user.role, "full_name": user.full_name};
        if user.hospital_id: claims["hospital_id"] = user.hospital_id;
        access_token = create_access_token(identity=user.user_id, additional_claims=claims);
        return jsonify(access_token=access_token, user=user.to_dict());
    else: return jsonify(error="Invalid credentials"), 401

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]; return User.query.get(identity)


## -- User Management (Supervisor Only) -- ##
@app.route('/api/users', methods=['GET'])
@roles_required(ROLES['SUPERVISOR'])
def get_users():
    try: users = User.query.options(joinedload(User.staff_profile)).all(); return jsonify([u.to_dict() for u in users]), 200;
    except Exception as e: app.logger.error(f"Err users: {e}"); return jsonify(error="Failed"), 500

@app.route('/api/users/<int:user_id>', methods=['GET', 'PUT', 'DELETE'])
@roles_required(ROLES['SUPERVISOR'])
def handle_user(user_id):
    user = User.query.get_or_404(user_id);
    if request.method == 'GET': return jsonify(user.to_dict());
    if request.method == 'PUT':
        data = request.get_json();
        if not data: return jsonify(error="Missing body"), 400;
        try:
            user.full_name = data.get('full_name', user.full_name); new_role = data.get('role');
            if new_role: user.role = new_role;
            if user.role == ROLES['HOSPITAL_STAFF']:
                hospital_id = data.get('hospital_id');
                if hospital_id: hospital = Hospital.query.get_or_404(hospital_id); user.hospital_id = hospital_id;
                else: user.hospital_id = None;
            else: user.hospital_id = None;
            db.session.commit(); return jsonify(user.to_dict()), 200;
        except ValueError as ve: db.session.rollback(); return jsonify(error=str(ve)), 400;
        except Exception as e: db.session.rollback(); app.logger.error(f"Err update user {user_id}: {e}"); return jsonify(error="Failed"), 500;
    if request.method == 'DELETE':
        try:
            db.session.delete(user); db.session.commit(); return '', 204;
        except Exception as e:
            db.session.rollback(); app.logger.error(f"Err delete user {user_id}: {e}");
            if 'foreign key constraint' in str(e).lower(): return jsonify(error="Cannot delete user: Referenced elsewhere."), 409;
            return jsonify(error="Failed"), 500


## -- Ambulance API Routes -- ##
@app.route('/api/ambulances', methods=['GET', 'POST'])
@jwt_required()
def handle_ambulances():
    if request.method == 'POST':
        # --- Simplified: Apply decorator directly ---
        @roles_required(ROLES['SUPERVISOR'], ROLES['DISPATCHER'])
        def post_ambulance():
            data=request.get_json()
            if not data or not data.get('license_plate'):return jsonify(error="Missing plate"),400
            if Ambulance.query.filter_by(license_plate=data['license_plate']).first():return jsonify(error="Plate exists"),409
            try:
                amb=Ambulance(license_plate=data['license_plate'],status=data.get('status','available'),current_lat=data.get('latitude'),current_lon=data.get('longitude'))
                db.session.add(amb); db.session.commit()
                socketio.emit('ambulance_update', amb.to_dict(), room='dashboard_updates') # Emit creation
                return jsonify(amb.to_dict()),201
            except ValueError as ve:db.session.rollback();return jsonify(error=str(ve)),400
            except Exception as e:db.session.rollback();app.logger.error(f"Err add amb: {e}");return jsonify(error="Internal error"),500
        return post_ambulance()

    # --- Simplified GET ---
    claims = get_jwt()
    user_role = claims.get("role", None)
    allowed_roles = [ROLES['SUPERVISOR'], ROLES['DISPATCHER'], ROLES['PARAMEDIC'], ROLES['HOSPITAL_STAFF']]
    if user_role not in allowed_roles:
         return jsonify(error=f"Unauthorized: Roles required: {', '.join(allowed_roles)}"), 403

    try:
        current_user_id = get_jwt_identity()
        app.logger.info(f"--- GET /api/ambulances ---")
        app.logger.info(f"User ID: {current_user_id}, Role: {user_role}")
        app.logger.info("Querying ambulances...")
        ambs=Ambulance.query.all()
        app.logger.info(f"Found {len(ambs)} ambulances.")
        results = [a.to_dict() for a in ambs]
        app.logger.info("Serialization complete.")
        return jsonify(results),200
    except Exception as e:
        app.logger.error(f"!!! Error in GET /api/ambulances: {e}", exc_info=True)
        return jsonify(error="Internal error"),500


@app.route('/api/ambulances/<int:ambulance_id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required()
def handle_ambulance(ambulance_id):
    amb = Ambulance.query.get_or_404(ambulance_id); user_role=get_jwt().get('role'); uid=get_jwt_identity()
    if request.method=='GET':
        allowed_roles = [ROLES['SUPERVISOR'], ROLES['DISPATCHER'], ROLES['PARAMEDIC'], ROLES['HOSPITAL_STAFF']]
        if user_role not in allowed_roles: return jsonify(error="Unauthorized"), 403
        return jsonify(amb.to_dict())

    if request.method=='PUT':
        @roles_required(ROLES['SUPERVISOR'], ROLES['DISPATCHER'], ROLES['PARAMEDIC'])
        def put_amb():
            data=request.get_json()
            if not data: return jsonify(error="Missing body"),400
            try:
                if user_role==ROLES['PARAMEDIC']:
                    sp=Staff.query.filter_by(user_id=uid).first()
                    if not sp or sp.assigned_ambulance_id!=ambulance_id: return jsonify(error="Paramedic can only update assigned amb."),403
                    amb.status=data.get('status',amb.status); amb.current_lat=data.get('latitude',amb.current_lat); amb.current_lon=data.get('longitude',amb.current_lon)
                else:
                    np=data.get('license_plate',amb.license_plate)
                    if np!=amb.license_plate and Ambulance.query.filter_by(license_plate=np).first(): return jsonify(error="Plate exists"),409
                    amb.license_plate=np; amb.status=data.get('status',amb.status); amb.current_lat=data.get('latitude',amb.current_lat); amb.current_lon=data.get('longitude',amb.current_lon)
                db.session.commit() # Triggers 'after_update'
                return jsonify(amb.to_dict())
            except ValueError as ve:db.session.rollback();return jsonify(error=str(ve)),400
            except Exception as e:db.session.rollback();app.logger.error(f"Err update amb {ambulance_id}: {e}");return jsonify(error="Internal error"),500
        return put_amb()

    if request.method=='DELETE':
        @roles_required(ROLES['SUPERVISOR'])
        def del_amb():
            try:
                db.session.delete(amb); db.session.commit()
                socketio.emit('ambulance_deleted', {'id': ambulance_id }, room='dashboard_updates')
                return '',204
            except Exception as e:
                db.session.rollback();app.logger.error(f"Err delete amb {ambulance_id}: {e}")
                if 'foreign key constraint' in str(e).lower(): return jsonify(error="Cannot delete: Amb assigned."),409
                return jsonify(error="Internal error"),500
        return del_amb()


## -- Hospital API Routes -- ##
@app.route('/api/hospitals', methods=['GET', 'POST'])
@jwt_required()
def handle_hospitals():
    if request.method=='POST':
        @roles_required(ROLES['SUPERVISOR'])
        def post_hosp():
            data=request.get_json()
            if not data or not data.get('name') or data.get('latitude') is None or data.get('longitude') is None: return jsonify(error="Missing fields"),400
            try:
                hosp=Hospital(name=data['name'],latitude=data['latitude'],longitude=data['longitude'],address=data.get('address'),er_capacity=data.get('er_capacity'),er_current_occupancy=data.get('er_current_occupancy',0))
                db.session.add(hosp); db.session.commit()
                socketio.emit('hospital_update', hosp.to_dict(), room='dashboard_updates')
                return jsonify(hosp.to_dict()),201
            except ValueError as ve:db.session.rollback();return jsonify(error=str(ve)),400
            except Exception as e:db.session.rollback();app.logger.error(f"Err add hosp: {e}");return jsonify(error="Internal error"),500
        return post_hosp()

    # Simplified GET
    claims = get_jwt(); user_role = claims.get("role", None)
    allowed_roles = [ROLES['SUPERVISOR'],ROLES['DISPATCHER'],ROLES['PARAMEDIC'],ROLES['HOSPITAL_STAFF']]
    if user_role not in allowed_roles: return jsonify(error="Unauthorized"), 403
    try: hosps=Hospital.query.all(); return jsonify([h.to_dict() for h in hosps]),200
    except Exception as e:app.logger.error(f"Err get hosp: {e}"); return jsonify(error="Internal error"),500


@app.route('/api/hospitals/<int:hospital_id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required()
def handle_hospital(hospital_id):
    hosp = Hospital.query.options(joinedload(Hospital.specialties)).get_or_404(hospital_id); role=get_jwt().get('role'); uid=get_jwt_identity()
    if request.method=='GET':
        allowed_roles = [ROLES['SUPERVISOR'],ROLES['DISPATCHER'],ROLES['PARAMEDIC'],ROLES['HOSPITAL_STAFF']]
        if role not in allowed_roles: return jsonify(error="Unauthorized"), 403
        return jsonify(hosp.to_dict())

    if request.method=='PUT':
        @roles_required(ROLES['SUPERVISOR'], ROLES['HOSPITAL_STAFF'])
        def put_hosp():
            user=User.query.get(uid)
            if role==ROLES['HOSPITAL_STAFF'] and user.hospital_id!=hospital_id: return jsonify(error="Staff can only update own hosp."),403
            data=request.get_json()
            if not data: return jsonify(error="Missing body"), 400
            try:
                hosp.name=data.get('name',hosp.name); hosp.address=data.get('address',hosp.address); hosp.latitude=data.get('latitude',hosp.latitude); hosp.longitude=data.get('longitude',hosp.longitude); hosp.er_capacity=data.get('er_capacity',hosp.er_capacity); hosp.er_current_occupancy=data.get('er_current_occupancy',hosp.er_current_occupancy)
                db.session.commit()
                socketio.emit('hospital_update', hosp.to_dict(), room='dashboard_updates')
                return jsonify(hosp.to_dict())
            except ValueError as ve:db.session.rollback();return jsonify(error=str(ve)),400
            except Exception as e:db.session.rollback();app.logger.error(f"Err update hosp {hospital_id}: {e}");return jsonify(error="Internal error"),500
        return put_hosp()

    if request.method=='DELETE':
        @roles_required(ROLES['SUPERVISOR'])
        def del_hosp():
            try:
                db.session.delete(hosp); db.session.commit()
                socketio.emit('hospital_deleted', {'id': hospital_id }, room='dashboard_updates')
                return '',204
            except Exception as e:
                db.session.rollback();app.logger.error(f"Err delete hosp {hospital_id}: {e}")
                if 'foreign key constraint' in str(e).lower(): return jsonify(error="Cannot delete: Hosp referenced."),409
                return jsonify(error="Internal error"),500
        return del_hosp()


## -- Incident API Routes -- ##
@app.route('/api/incidents', methods=['GET', 'POST'])
@jwt_required()
def handle_incidents():
    role=get_jwt().get('role'); uid=get_jwt_identity()
    if request.method=='POST':
        @roles_required(ROLES['SUPERVISOR'], ROLES['DISPATCHER'])
        def post_inc():
            data=request.get_json()
            if not data or data.get('location_lat') is None or data.get('location_lon') is None: return jsonify(error="Missing location"),400
            try:
                aid=data.get('ambulance_id'); hid=data.get('hospital_id')
                if aid and not Ambulance.query.get(aid): return jsonify(error=f"Amb ID {aid} not found"),404
                if hid and not Hospital.query.get(hid): return jsonify(error=f"Hosp ID {hid} not found"),404
                pat=Patient(full_name=data.get('patient_name'),dob=data.get('patient_dob'),blood_type=data.get('patient_blood_type')); db.session.add(pat); db.session.flush()
                inc=Incident(patient_id=pat.patient_id, location_lat=data['location_lat'], location_lon=data['location_lon'], location_description=data.get('description'), dispatcher_id=uid, ambulance_id=aid, destination_hospital_id=hid, status=data.get('status','active')); db.session.add(inc); db.session.commit()
                res=Incident.query.options(joinedload(Incident.patient), joinedload(Incident.ambulance), joinedload(Incident.destination_hospital), joinedload(Incident.dispatcher)).get(inc.incident_id); # Eager load for emit
                socketio.emit('incident_update', res.to_dict(include_details=True), room='dashboard_updates')
                return jsonify(res.to_dict(include_details=True)),201
            except ValueError as ve:db.session.rollback();return jsonify(error=str(ve)),400
            except Exception as e:db.session.rollback();app.logger.error(f"Err create inc: {e}");return jsonify(error="Internal error"),500
        return post_inc()

    # Simplified GET
    claims = get_jwt(); user_role = claims.get("role", None)
    allowed_roles = [ROLES['SUPERVISOR'],ROLES['DISPATCHER'],ROLES['PARAMEDIC'],ROLES['HOSPITAL_STAFF']]
    if user_role not in allowed_roles: return jsonify(error="Unauthorized"), 403
    try:
        q=Incident.query.options(joinedload(Incident.patient), joinedload(Incident.ambulance), joinedload(Incident.destination_hospital), joinedload(Incident.dispatcher)); # Eager load
        u=User.query.get(uid)
        if role==ROLES['PARAMEDIC']:
            sp=Staff.query.filter_by(user_id=uid).first()
            if sp and sp.assigned_ambulance_id: q=q.filter(Incident.ambulance_id==sp.assigned_ambulance_id, Incident.status.notin_(['closed','cancelled']))
            else: return jsonify([]),200
        elif role==ROLES['HOSPITAL_STAFF']:
            if u.hospital_id: q=q.filter(Incident.destination_hospital_id==u.hospital_id, Incident.status=='en_route_to_hospital') # Only incoming
            else: return jsonify([]),200
        incs=q.order_by(Incident.incident_time.desc()).all()
        return jsonify([i.to_dict(include_details=True) for i in incs]),200
    except Exception as e:app.logger.error(f"Err get incs: {e}");return jsonify(error="Internal error"),500


@app.route('/api/incidents/<int:incident_id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required()
def handle_incident(incident_id):
    inc=Incident.query.options(joinedload(Incident.patient),joinedload(Incident.ambulance),joinedload(Incident.destination_hospital),joinedload(Incident.dispatcher)).get_or_404(incident_id)
    role=get_jwt().get('role')
    uid=get_jwt_identity()
    allowed=False
    if role in [ROLES['SUPERVISOR'],ROLES['DISPATCHER']]:
        allowed=True
    elif role==ROLES['PARAMEDIC']:
        sp=Staff.query.filter_by(user_id=uid).first()
        if sp and sp.assigned_ambulance_id==inc.ambulance_id:
             allowed=True
    elif role==ROLES['HOSPITAL_STAFF']:
        u=User.query.get(uid)
        if u and u.hospital_id==inc.destination_hospital_id:
             allowed=True
    if not allowed: return jsonify(error="Unauthorized access"),403

    if request.method=='GET': return jsonify(inc.to_dict(include_details=True))

    if request.method=='PUT':
        if role not in [ROLES['SUPERVISOR'],ROLES['DISPATCHER'],ROLES['PARAMEDIC']]: return jsonify(error="Unauthorized update"),403
        data=request.get_json()
        if not data: return jsonify(error="Missing body"), 400
        try:
            if role==ROLES['PARAMEDIC']:
                ns=data.get('status')
                if ns: inc.status=ns # Validation in model
                inc.location_description=data.get('description',inc.location_description) # Paramedic can update description
            else: # Supervisor/Dispatcher
                aid=data.get('ambulance_id'); hid=data.get('hospital_id')
                if aid == '': aid = None # Allow unassigning
                if hid == '': hid = None # Allow unassigning
                if aid is not None and not Ambulance.query.get(aid):return jsonify(error=f"Amb ID {aid} not found"),404
                if hid is not None and not Hospital.query.get(hid):return jsonify(error=f"Hosp ID {hid} not found"),404
                inc.ambulance_id=aid; inc.destination_hospital_id=hid; inc.location_description=data.get('description',inc.location_description); ns=data.get('status')
                if ns: inc.status=ns
            db.session.commit() # Triggers 'set' event
            res=Incident.query.options(joinedload(Incident.patient), joinedload(Incident.ambulance), joinedload(Incident.destination_hospital), joinedload(Incident.dispatcher)).get(incident_id)
            return jsonify(res.to_dict(include_details=True)),200
        except ValueError as ve:db.session.rollback();return jsonify(error=str(ve)),400
        except Exception as e:db.session.rollback();app.logger.error(f"Err update inc {incident_id}: {e}");return jsonify(error="Internal error"),500

    if request.method=='DELETE':
        @roles_required(ROLES['SUPERVISOR'])
        def del_inc():
            try:
                db.session.delete(inc); db.session.commit()
                socketio.emit('incident_deleted', {'id': incident_id }, room='dashboard_updates')
                return '',204
            except Exception as e:db.session.rollback();app.logger.error(f"Err delete inc {incident_id}: {e}");return jsonify(error="Internal error"),500
        return del_inc()


## -- Patient Vitals API Routes -- ##
@app.route('/api/incidents/<int:incident_id>/vitals', methods=['GET', 'POST'])
@jwt_required()
def handle_incident_vitals(incident_id):
    inc=Incident.query.get_or_404(incident_id); role=get_jwt().get('role'); uid=get_jwt_identity()
    if request.method=='POST':
        allowed=False
        if role==ROLES['SUPERVISOR']: allowed=True
        elif role==ROLES['PARAMEDIC']:
            sp=Staff.query.filter_by(user_id=uid).first()
            if sp and sp.assigned_ambulance_id==inc.ambulance_id: allowed=True
        if not allowed: return jsonify(error="Unauthorized add vitals"),403
        data=request.get_json();
        if not data:return jsonify(error="Missing data"),400
        try:
            hr=data.get('heart_rate');bps=data.get('blood_pressure_systolic');bpd=data.get('blood_pressure_diastolic');o2=data.get('oxygen_saturation')
            if hr is not None and not isinstance(hr,(int,float)):raise ValueError("HR must be number.")
            if bps is not None and not isinstance(bps,(int,float)):raise ValueError("BP Sys must be number.")
            if bpd is not None and not isinstance(bpd,(int,float)):raise ValueError("BP Dia must be number.")
            if o2 is not None and not isinstance(o2,(int,float)):raise ValueError("O2 Sat must be number.")
            v=PatientVitalsLog(incident_id=incident_id,heart_rate=hr,blood_pressure_systolic=bps,blood_pressure_diastolic=bpd,oxygen_saturation=o2)
            db.session.add(v); db.session.commit()
            socketio.emit('vitals_update', v.to_dict(), room=f'incident_{incident_id}')
            socketio.emit('vitals_update', v.to_dict(), room='dashboard_updates')
            return jsonify(v.to_dict()),201
        except ValueError as ve:db.session.rollback();return jsonify(error=str(ve)),400
        except Exception as e:db.session.rollback();app.logger.error(f"Err add vitals I{incident_id}: {e}");return jsonify(error="Internal error"),500
    # GET
    allowed_view=False
    if role in [ROLES['SUPERVISOR'],ROLES['DISPATCHER']]: allowed_view=True
    elif role==ROLES['PARAMEDIC']:
        sp=Staff.query.filter_by(user_id=uid).first()
        if sp and sp.assigned_ambulance_id==inc.ambulance_id: allowed_view=True
    elif role==ROLES['HOSPITAL_STAFF']:
        u=User.query.get(uid)
        if u and u.hospital_id==inc.destination_hospital_id: allowed_view=True
    if not allowed_view: return jsonify(error="Unauthorized view vitals"),403
    try:
        vs=PatientVitalsLog.query.filter_by(incident_id=incident_id).order_by(PatientVitalsLog.timestamp.desc()).all()
        return jsonify([v.to_dict() for v in vs]),200
    except Exception as e:app.logger.error(f"Err get vitals I{incident_id}: {e}");return jsonify(error="Internal error"),500


## -- Staff API Routes -- ##
@app.route('/api/staff', methods=['GET', 'POST'])
@roles_required(ROLES['SUPERVISOR'])
def handle_staff():
    if request.method=='POST':
        data=request.get_json()
        if not data or data.get('user_id') is None: return jsonify(error="Missing user_id"),400
        u=User.query.get_or_404(data['user_id'])
        if Staff.query.filter_by(user_id=data['user_id']).first(): return jsonify(error=f"User {data['user_id']} is staff"),409
        aid=data.get('assigned_ambulance_id')
        if aid == '': aid = None
        if aid is not None and not Ambulance.query.get(aid): return jsonify(error=f"Amb ID {aid} not found"),404
        try:
            s=Staff(user_id=data['user_id'],certification_level=data.get('certification_level'),assigned_ambulance_id=aid)
            db.session.add(s); db.session.commit()
            res=Staff.query.options(joinedload(Staff.user)).get(s.staff_id)
            return jsonify(res.to_dict()),201
        except ValueError as ve:db.session.rollback();return jsonify(error=str(ve)),400
        except Exception as e:db.session.rollback();app.logger.error(f"Err add staff: {e}");return jsonify(error="Internal error"),500
    # GET
    try: ss=Staff.query.options(joinedload(Staff.user)).all(); return jsonify([s.to_dict() for s in ss]),200
    except Exception as e:app.logger.error(f"Err get staff: {e}");return jsonify(error="Internal error"),500

@app.route('/api/staff/<int:staff_id>', methods=['GET', 'PUT', 'DELETE'])
@roles_required(ROLES['SUPERVISOR'])
def handle_single_staff(staff_id):
    sm=Staff.query.options(joinedload(Staff.user)).get_or_404(staff_id)
    if request.method=='GET': return jsonify(sm.to_dict())
    if request.method=='PUT':
        data=request.get_json();
        if not data:return jsonify(error="Missing body"),400
        try:
            sm.certification_level=data.get('certification_level',sm.certification_level)
            aid=data.get('assigned_ambulance_id');
            if aid=='':aid=None
            if aid is not None: Ambulance.query.get_or_404(aid)
            sm.assigned_ambulance_id=aid
            db.session.commit()
            res=Staff.query.options(joinedload(Staff.user)).get(staff_id)
            return jsonify(res.to_dict()),200
        except ValueError as ve:db.session.rollback();return jsonify(error=str(ve)),400
        except Exception as e:db.session.rollback();app.logger.error(f"Err update staff {staff_id}: {e}");return jsonify(error="Internal error"),500
    if request.method=='DELETE':
        try:
            db.session.delete(sm); db.session.commit(); return '',204
        except Exception as e:
            db.session.rollback();app.logger.error(f"Err delete staff {staff_id}: {e}")
            return jsonify(error="Internal error"),500


## -- Ambulance Equipment API Routes -- ##
@app.route('/api/ambulances/<int:ambulance_id>/equipment', methods=['GET', 'POST'])
@jwt_required()
def handle_ambulance_equipment(ambulance_id):
    amb=Ambulance.query.get_or_404(ambulance_id); role=get_jwt().get('role'); uid=get_jwt_identity()
    if request.method=='POST':
        allowed=False
        if role==ROLES['SUPERVISOR']:allowed=True
        elif role==ROLES['PARAMEDIC']:
            sp=Staff.query.filter_by(user_id=uid).first();
            if sp and sp.assigned_ambulance_id==ambulance_id:allowed=True
        if not allowed: return jsonify(error="Unauthorized"),403
        data=request.get_json();
        if not data or not data.get('equipment_name'):
            return jsonify(error="Missing name"),400
        try:
            eq=Equipment(ambulance_id=ambulance_id,equipment_name=data['equipment_name'],status=data.get('status','operational'))
            db.session.add(eq); db.session.commit(); return jsonify(eq.to_dict()),201
        except ValueError as ve:db.session.rollback();return jsonify(error=str(ve)),400
        except Exception as e:db.session.rollback();app.logger.error(f"Err add equip A{ambulance_id}: {e}");return jsonify(error="Internal error"),500
    # GET
    if role not in [ROLES['SUPERVISOR'],ROLES['DISPATCHER'],ROLES['PARAMEDIC']]:return jsonify(error="Unauthorized"),403
    try: eqs=Equipment.query.filter_by(ambulance_id=ambulance_id).all(); return jsonify([e.to_dict() for e in eqs]),200
    except Exception as e:app.logger.error(f"Err get equip A{ambulance_id}: {e}");return jsonify(error="Internal error"),500

@app.route('/api/equipment/<int:equipment_id>', methods=['PUT', 'DELETE'])
@roles_required(ROLES['SUPERVISOR'], ROLES['PARAMEDIC'])
def handle_single_equipment(equipment_id):
    eq=Equipment.query.get_or_404(equipment_id); role=get_jwt().get('role'); uid=get_jwt_identity()
    if role==ROLES['PARAMEDIC']:
        sp=Staff.query.filter_by(user_id=uid).first()
        if not sp or sp.assigned_ambulance_id!=eq.ambulance_id: return jsonify(error="Paramedic can only manage equip on assigned amb."),403
    if request.method=='PUT':
        data=request.get_json();
        if not data:return jsonify(error="Missing body"),400
        try:
            eq.equipment_name=data.get('equipment_name',eq.equipment_name); # Allow supervisor to rename
            eq.status=data.get('status',eq.status); # Validation in model
            db.session.commit(); return jsonify(eq.to_dict())
        except ValueError as ve:db.session.rollback();return jsonify(error=str(ve)),400
        except Exception as e:db.session.rollback();app.logger.error(f"Err update equip {equipment_id}: {e}");return jsonify(error="Internal error"),500
    if request.method=='DELETE':
        if role!=ROLES['SUPERVISOR']: return jsonify(error="Only supervisors can delete equip."),403
        try: db.session.delete(eq); db.session.commit(); return '',204
        except Exception as e:db.session.rollback();app.logger.error(f"Err delete equip {equipment_id}: {e}");return jsonify(error="Internal error"),500


## -- Hospital Specialties API Routes -- ##
@app.route('/api/hospitals/<int:hospital_id>/specialties', methods=['GET', 'POST'])
@jwt_required()
def handle_hospital_specialties(hospital_id):
    hosp=Hospital.query.get_or_404(hospital_id); role=get_jwt().get('role'); uid=get_jwt_identity()
    if request.method=='POST':
        allowed=False
        if role==ROLES['SUPERVISOR']:allowed=True
        elif role==ROLES['HOSPITAL_STAFF']:
            u=User.query.get(uid);
            if u and u.hospital_id==hospital_id:allowed=True
        if not allowed: return jsonify(error="Unauthorized"),403
        data=request.get_json();
        if not data or not data.get('specialty_name'):
            return jsonify(error="Missing name"),400
        try:
            existing = HospitalSpecialties.query.filter_by(hospital_id=hospital_id, specialty_name=data['specialty_name']).first()
            if existing: return jsonify(error="Specialty already exists for this hospital"), 409
            spec=HospitalSpecialties(hospital_id=hospital_id,specialty_name=data['specialty_name'],is_available=data.get('is_available',True))
            db.session.add(spec); db.session.commit(); return jsonify(spec.to_dict()),201
        except Exception as e:db.session.rollback();app.logger.error(f"Err add spec H{hospital_id}: {e}");return jsonify(error="Internal error"),500
    # GET
    if role not in [ROLES['SUPERVISOR'],ROLES['DISPATCHER'],ROLES['HOSPITAL_STAFF'],ROLES['PARAMEDIC']]:return jsonify(error="Unauthorized"),403
    try: specs=HospitalSpecialties.query.filter_by(hospital_id=hospital_id).all(); return jsonify([s.to_dict() for s in specs]),200
    except Exception as e:app.logger.error(f"Err get spec H{hospital_id}: {e}");return jsonify(error="Internal error"),500

@app.route('/api/specialties/<int:specialty_id>', methods=['PUT', 'DELETE'])
@jwt_required()
def handle_single_specialty(specialty_id):
    spec=HospitalSpecialties.query.get_or_404(specialty_id); role=get_jwt().get('role'); uid=get_jwt_identity()
    allowed=False
    if role==ROLES['SUPERVISOR']:allowed=True
    elif role==ROLES['HOSPITAL_STAFF']:
        u=User.query.get(uid);
        if u and u.hospital_id==spec.hospital_id:allowed=True
    if not allowed: return jsonify(error="Unauthorized"),403
    if request.method=='PUT':
        data=request.get_json();
        if not data:return jsonify(error="Missing body"),400
        try:
            new_name = data.get('specialty_name', spec.specialty_name)
            if new_name != spec.specialty_name:
                existing = HospitalSpecialties.query.filter_by(hospital_id=spec.hospital_id, specialty_name=new_name).first()
                if existing: return jsonify(error="Another specialty with this name already exists for this hospital"), 409
            spec.specialty_name = new_name
            if 'is_available' in data and isinstance(data['is_available'], bool):
                 spec.is_available = data['is_available']
            elif 'is_available' in data:
                 return jsonify(error="is_available must be true or false"), 400
            else: pass # No change if not provided
            db.session.commit(); return jsonify(spec.to_dict())
        except Exception as e:db.session.rollback();app.logger.error(f"Err update spec {specialty_id}: {e}");return jsonify(error="Internal error"),500
    if request.method=='DELETE':
        if role!=ROLES['SUPERVISOR']: return jsonify(error="Only supervisors can delete specs."),403
        try: db.session.delete(spec); db.session.commit(); return '',204
        except Exception as e:db.session.rollback();app.logger.error(f"Err delete spec {specialty_id}: {e}");return jsonify(error="Internal error"),500


## -- Simulated Dispatch Suggestion Route -- ##
def calculate_distance(lat1, lon1, lat2, lon2):
    R=6371; # Earth radius in km
    try:
        la1=math.radians(float(lat1)); lo1=math.radians(float(lon1))
        la2=math.radians(float(lat2)); lo2=math.radians(float(lon2))
        dlo=lo2-lo1; dla=la2-la1
        a=math.sin(dla/2)**2+math.cos(la1)*math.cos(la2)*math.sin(dlo/2)**2
        c=2*math.atan2(math.sqrt(a),math.sqrt(1-a))
        dist=R*c
        return dist
    except(TypeError,ValueError):
        return float('inf')

@app.route('/api/dispatch/suggest', methods=['POST'])
@roles_required(ROLES['SUPERVISOR'], ROLES['DISPATCHER'])
def suggest_ambulance():
    data = request.get_json()
    incident_lat = data.get('latitude'); incident_lon = data.get('longitude')
    if incident_lat is None or incident_lon is None: return jsonify(error="Missing location"), 400
    try:
        available_ambulances = Ambulance.query.filter_by(status='available').all()
        if not available_ambulances: return jsonify(suggestion=None, message="No available ambulances."), 200
        nearest_ambulance = None; min_distance = float('inf')
        for amb in available_ambulances:
            if amb.current_lat is not None and amb.current_lon is not None:
                distance = calculate_distance(incident_lat, incident_lon, amb.current_lat, amb.current_lon)
                if distance < min_distance: min_distance = distance; nearest_ambulance = amb
        if nearest_ambulance:
            avg_speed_kmh = 40; estimated_time_hours = min_distance / avg_speed_kmh if avg_speed_kmh > 0 else 0
            estimated_eta = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=estimated_time_hours)
            suggestion = nearest_ambulance.to_dict()
            suggestion['estimated_distance_km'] = round(min_distance, 2)
            suggestion['estimated_eta'] = estimated_eta.isoformat()
            return jsonify(suggestion=suggestion), 200
        else: return jsonify(suggestion=None, message="No available ambulances with location found."), 200
    except Exception as e: app.logger.error(f"Error suggesting ambulance: {e}"); return jsonify(error="Internal error"), 500


## -- WebSocket Event Handlers -- ##

@socketio.on('connect')
def handle_connect():
    sid = request.sid
    try:
        verify_jwt_in_request(optional=True) # Check for token but don't fail if absent yet
        current_user_id = get_jwt_identity()
        if current_user_id:
            user = User.query.get(current_user_id)
            if user:
                logging.info(f"Authenticated client connected: SID {sid}, User {user.username}")
                join_room(f'user_{current_user_id}')
                if user.role == ROLES['HOSPITAL_STAFF'] and user.hospital_id:
                    join_room(f'hospital_{user.hospital_id}')
            else: # Token valid but user deleted?
                 logging.warning(f"Client connected with valid token for non-existent user ID {current_user_id}: SID {sid}")
                 join_room('dashboard_updates') # Join general room anyway?
                 return
        else: # No token or invalid token
            logging.info(f"Anonymous/Unauthenticated client connected: SID {sid}")
            join_room('dashboard_updates')

        logging.info(f"Client {sid} joined room 'dashboard_updates'")

    except Exception as e: # Catch errors during JWT verification etc.
        logging.error(f"Error during WS connect/auth for SID {sid}: {e}")
        # Consider disconnecting if auth is strictly required: disconnect(sid)


@socketio.on('disconnect')
def handle_disconnect():
    logging.info(f"Client disconnected: {request.sid}")

@socketio.on('join_incident_room')
def handle_join_incident_room(data):
    try:
        verify_jwt_in_request()
        incident_id = data.get('incident_id')
        if not incident_id: return
        uid = get_jwt_identity()
        user = User.query.get(uid)
        if not user:
             logging.warning(f"Unauthorized attempt to join incident room by SID {request.sid}")
             return

        room_name = f'incident_{incident_id}'
        join_room(room_name)
        logging.info(f"Client {request.sid} (User {uid}) joined room {room_name}")

    except Exception as e:
        logging.error(f"Error joining incident room for SID {request.sid}: {e}")

@socketio.on('leave_incident_room')
def handle_leave_incident_room(data):
     try:
         incident_id = data.get('incident_id')
         if not incident_id: return
         room_name = f'incident_{incident_id}'
         leave_room(room_name)
         logging.info(f"Client {request.sid} left room {room_name}")
     except Exception as e:
         logging.error(f"Error leaving incident room for SID {request.sid}: {e}")


if __name__ == '__main__':
    with app.app_context():
        try: db.create_all(); print("DB tables checked/created.")
        except Exception as e: print(f"Error during db.create_all(): {e}")
    print("Starting Flask-SocketIO server...")
    # Use SocketIO's run method, ensure eventlet is installed
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, use_reloader=True)
