from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from config import Config
import datetime

app = Flask(__name__)
app.config.from_object(Config)
# --- 1. ADD FLASK-CORS ---
from flask_cors import CORS
CORS(app) # Enable CORS for all routes
# --- END CORS ADDITION ---
db = SQLAlchemy(app)


## -- Models -- ##

class Ambulance(db.Model):
    __tablename__ = 'ambulances'
    ambulance_id = db.Column(db.Integer, primary_key=True)
    license_plate = db.Column(db.String(20), unique=True, nullable=False)
    status = db.Column(db.String(50), nullable=False, default='available')
    current_lat = db.Column(db.DECIMAL(10, 8))
    current_lon = db.Column(db.DECIMAL(11, 8))

    def to_dict(self):
        return {
            'id': self.ambulance_id,
            'license_plate': self.license_plate,
            'status': self.status,
            'latitude': str(self.current_lat) if self.current_lat else None,
            'longitude': str(self.current_lon) if self.current_lon else None
        }

class Hospital(db.Model):
    __tablename__ = 'hospitals'
    hospital_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(255))
    latitude = db.Column(db.DECIMAL(10, 8), nullable=False)
    longitude = db.Column(db.DECIMAL(11, 8), nullable=False)
    er_capacity = db.Column(db.Integer)
    er_current_occupancy = db.Column(db.Integer)

    def to_dict(self):
        return {
            'id': self.hospital_id,
            'name': self.name,
            'address': self.address,
            'latitude': str(self.latitude) if self.latitude else None,
            'longitude': str(self.longitude) if self.longitude else None,
            'er_capacity': self.er_capacity,
            'er_current_occupancy': self.er_current_occupancy
        }

class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(50), nullable=False)

    def to_dict(self):
        return {
            'id': self.user_id,
            'username': self.username,
            'full_name': self.full_name,
            'role': self.role
        }

class Patient(db.Model):
    __tablename__ = 'patients'
    patient_id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100))
    dob = db.Column(db.Date)
    blood_type = db.Column(db.String(5))

    def to_dict(self):
        return {
            'id': self.patient_id,
            'full_name': self.full_name,
            'dob': str(self.dob) if self.dob else None,
            'blood_type': self.blood_type
        }

class Incident(db.Model):
    __tablename__ = 'incidents'
    incident_id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.patient_id'))
    dispatcher_id = db.Column(db.Integer, db.ForeignKey('users.user_id'))
    ambulance_id = db.Column(db.Integer, db.ForeignKey('ambulances.ambulance_id'))
    destination_hospital_id = db.Column(db.Integer, db.ForeignKey('hospitals.hospital_id'))
    location_lat = db.Column(db.DECIMAL(10, 8), nullable=False)
    location_lon = db.Column(db.DECIMAL(11, 8), nullable=False)
    location_description = db.Column(db.Text)
    incident_time = db.Column(db.TIMESTAMP, server_default=db.func.now())
    status = db.Column(db.String(50), nullable=False, default='active')

    # Relationship to automatically fetch associated vitals logs
    vitals_logs = db.relationship('PatientVitalsLog', backref='incident', lazy=True, cascade="all, delete-orphan")


    def to_dict(self):
        return {
            'id': self.incident_id,
            'patient_id': self.patient_id,
            'dispatcher_id': self.dispatcher_id,
            'ambulance_id': self.ambulance_id,
            'destination_hospital_id': self.destination_hospital_id,
            'latitude': str(self.location_lat) if self.location_lat else None,
            'longitude': str(self.location_lon) if self.location_lon else None,
            'description': self.location_description,
            'incident_time': self.incident_time.isoformat() if self.incident_time else None,
            'status': self.status
        }

class PatientVitalsLog(db.Model):
    __tablename__ = 'patient_vitals_log'
    log_id = db.Column(db.BigInteger, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey('incidents.incident_id'), nullable=False)
    timestamp = db.Column(db.TIMESTAMP, server_default=db.func.now())
    heart_rate = db.Column(db.Integer)
    blood_pressure_systolic = db.Column(db.Integer)
    blood_pressure_diastolic = db.Column(db.Integer)
    oxygen_saturation = db.Column(db.DECIMAL(5, 2))

    def to_dict(self):
        return {
            'log_id': self.log_id,
            'incident_id': self.incident_id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'heart_rate': self.heart_rate,
            'blood_pressure_systolic': self.blood_pressure_systolic,
            'blood_pressure_diastolic': self.blood_pressure_diastolic,
            'oxygen_saturation': str(self.oxygen_saturation) if self.oxygen_saturation else None
        }

class Staff(db.Model):
    __tablename__ = 'staff'
    staff_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False, unique=True)
    certification_level = db.Column(db.String(50))
    assigned_ambulance_id = db.Column(db.Integer, db.ForeignKey('ambulances.ambulance_id'))

    def to_dict(self):
        return {
            'staff_id': self.staff_id,
            'user_id': self.user_id,
            'certification_level': self.certification_level,
            'assigned_ambulance_id': self.assigned_ambulance_id
        }

class Equipment(db.Model):
    __tablename__ = 'equipment'
    equipment_id = db.Column(db.Integer, primary_key=True)
    ambulance_id = db.Column(db.Integer, db.ForeignKey('ambulances.ambulance_id'), nullable=False)
    equipment_name = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(50), nullable=False, default='operational')

    def to_dict(self):
        return {
            'equipment_id': self.equipment_id,
            'ambulance_id': self.ambulance_id,
            'equipment_name': self.equipment_name,
            'status': self.status
        }

class HospitalSpecialties(db.Model):
    __tablename__ = 'hospital_specialties'
    specialty_id = db.Column(db.Integer, primary_key=True)
    hospital_id = db.Column(db.Integer, db.ForeignKey('hospitals.hospital_id'), nullable=False)
    specialty_name = db.Column(db.String(100), nullable=False)
    is_available = db.Column(db.Boolean, default=True)

    def to_dict(self):
        return {
            'specialty_id': self.specialty_id,
            'hospital_id': self.hospital_id,
            'specialty_name': self.specialty_name,
            'is_available': self.is_available
        }


## -- Ambulance API Routes -- ##

@app.route('/api/ambulances', methods=['GET', 'POST'])
def handle_ambulances():
    if request.method == 'POST':
        data = request.get_json()
        if not data or not 'license_plate' in data:
            return jsonify(error="Missing license_plate in request body"), 400

        new_ambulance = Ambulance(
            license_plate=data['license_plate'],
            status=data.get('status', 'available'),
            current_lat=data.get('latitude'),
            current_lon=data.get('longitude')
        )
        try:
            db.session.add(new_ambulance)
            db.session.commit()
            return jsonify(new_ambulance.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            return jsonify(error=str(e)), 500

    # GET Request
    try:
        all_ambulances = Ambulance.query.all()
        results = [ambulance.to_dict() for ambulance in all_ambulances]
        return jsonify(results), 200
    except Exception as e:
        return jsonify(error=str(e)), 500


@app.route('/api/ambulances/<int:ambulance_id>', methods=['GET', 'PUT', 'DELETE'])
def handle_ambulance(ambulance_id):
    ambulance = Ambulance.query.get_or_404(ambulance_id)

    if request.method == 'GET':
        return jsonify(ambulance.to_dict())

    if request.method == 'PUT':
        data = request.get_json()
        try:
            ambulance.license_plate = data.get('license_plate', ambulance.license_plate)
            ambulance.status = data.get('status', ambulance.status)
            ambulance.current_lat = data.get('latitude', ambulance.current_lat)
            ambulance.current_lon = data.get('longitude', ambulance.current_lon)
            db.session.commit()
            return jsonify(ambulance.to_dict())
        except Exception as e:
            db.session.rollback()
            return jsonify(error=str(e)), 500

    if request.method == 'DELETE':
        try:
            db.session.delete(ambulance)
            db.session.commit()
            return '', 204
        except Exception as e:
            db.session.rollback()
            return jsonify(error=str(e)), 500


## -- Hospital API Routes -- ##

@app.route('/api/hospitals', methods=['GET', 'POST'])
def handle_hospitals():
    if request.method == 'POST':
        data = request.get_json()
        if not data or not all(k in data for k in ('name', 'latitude', 'longitude')):
            return jsonify(error="Missing required fields: name, latitude, longitude"), 400

        new_hospital = Hospital(
            name=data['name'],
            latitude=data['latitude'],
            longitude=data['longitude'],
            address=data.get('address'),
            er_capacity=data.get('er_capacity'),
            er_current_occupancy=data.get('er_current_occupancy', 0)
        )
        try:
            db.session.add(new_hospital)
            db.session.commit()
            return jsonify(new_hospital.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            return jsonify(error=str(e)), 500

    # GET Request
    try:
        all_hospitals = Hospital.query.all()
        results = [hospital.to_dict() for hospital in all_hospitals]
        return jsonify(results), 200
    except Exception as e:
        return jsonify(error=str(e)), 500


@app.route('/api/hospitals/<int:hospital_id>', methods=['GET', 'PUT', 'DELETE'])
def handle_hospital(hospital_id):
    hospital = Hospital.query.get_or_404(hospital_id)

    if request.method == 'GET':
        return jsonify(hospital.to_dict())

    if request.method == 'PUT':
        data = request.get_json()
        try:
            hospital.name = data.get('name', hospital.name)
            hospital.address = data.get('address', hospital.address)
            hospital.latitude = data.get('latitude', hospital.latitude)
            hospital.longitude = data.get('longitude', hospital.longitude)
            hospital.er_capacity = data.get('er_capacity', hospital.er_capacity)
            hospital.er_current_occupancy = data.get('er_current_occupancy', hospital.er_current_occupancy)
            db.session.commit()
            return jsonify(hospital.to_dict())
        except Exception as e:
            db.session.rollback()
            return jsonify(error=str(e)), 500

    if request.method == 'DELETE':
        try:
            # Maybe add logic here later to check if hospital is assigned to active incidents
            db.session.delete(hospital)
            db.session.commit()
            return '', 204
        except Exception as e:
            db.session.rollback()
            return jsonify(error=str(e)), 500

## -- Incident API Routes -- ##

@app.route('/api/incidents', methods=['GET', 'POST'])
def handle_incidents():
    if request.method == 'POST':
        data = request.get_json()
        if not data or 'location_lat' not in data or 'location_lon' not in data:
            return jsonify(error="Missing required location data"), 400

        try:
            # Step 1: Create a new patient
            new_patient = Patient(
                full_name=data.get('patient_name'),
                dob=data.get('patient_dob'),
                blood_type=data.get('patient_blood_type')
            )
            db.session.add(new_patient)
            db.session.flush() # Flush to get the patient_id

            # Step 2: Create the incident
            new_incident = Incident(
                patient_id=new_patient.patient_id,
                location_lat=data['location_lat'],
                location_lon=data['location_lon'],
                location_description=data.get('description'),
                dispatcher_id=data.get('dispatcher_id'),
                ambulance_id=data.get('ambulance_id'),
                destination_hospital_id=data.get('hospital_id')
            )
            db.session.add(new_incident)
            db.session.commit()

            return jsonify(new_incident.to_dict()), 201

        except Exception as e:
            db.session.rollback()
            # Be more specific about foreign key errors if possible
            error_str = str(e)
            if 'foreign key constraint fails' in error_str.lower():
                 return jsonify(error=f"Invalid ID provided. Ensure Ambulance, Hospital, and Dispatcher IDs exist. Details: {error_str}"), 400
            return jsonify(error=error_str), 500

    # GET Request
    try:
        all_incidents = Incident.query.all()
        results = [incident.to_dict() for incident in all_incidents]
        return jsonify(results), 200
    except Exception as e:
        return jsonify(error=str(e)), 500

# --- MODIFIED ROUTE BELOW ---
@app.route('/api/incidents/<int:incident_id>', methods=['GET', 'PUT', 'DELETE']) # Added DELETE
def handle_incident(incident_id):
    incident = Incident.query.get_or_404(incident_id)

    if request.method == 'GET':
        return jsonify(incident.to_dict())

    if request.method == 'PUT':
        data = request.get_json()
        try:
            # Note: Do not update patient_id via this route
            incident.dispatcher_id = data.get('dispatcher_id', incident.dispatcher_id)
            incident.ambulance_id = data.get('ambulance_id', incident.ambulance_id)
            incident.destination_hospital_id = data.get('hospital_id', incident.destination_hospital_id)
            incident.location_description = data.get('description', incident.location_description)
            incident.status = data.get('status', incident.status)

            db.session.commit()
            return jsonify(incident.to_dict()), 200
        except Exception as e:
            db.session.rollback()
            error_str = str(e)
            if 'foreign key constraint fails' in error_str.lower():
                 return jsonify(error=f"Invalid ID provided for update. Ensure Ambulance, Hospital, Dispatcher IDs exist. Details: {error_str}"), 400
            return jsonify(error=error_str), 500

    # --- NEW DELETE LOGIC ---
    if request.method == 'DELETE':
        try:
            # Vitals logs will be deleted automatically due to cascade="all, delete-orphan" on the relationship
            db.session.delete(incident)
            # Potentially delete the associated Patient record if it's not used elsewhere
            # patient = Patient.query.get(incident.patient_id)
            # if patient: db.session.delete(patient) # Be careful if patients can have multiple incidents
            db.session.commit()
            return '', 204 # No Content
        except Exception as e:
            db.session.rollback()
            return jsonify(error=str(e)), 500


## -- Patient Vitals API Routes -- ##

@app.route('/api/incidents/<int:incident_id>/vitals', methods=['GET', 'POST'])
def handle_incident_vitals(incident_id):
    # Check if the incident exists first
    Incident.query.get_or_404(incident_id)

    if request.method == 'POST':
        data = request.get_json()
        if not data:
            return jsonify(error="Missing data"), 400

        try:
            new_vitals = PatientVitalsLog(
                incident_id=incident_id,
                heart_rate=data.get('heart_rate'),
                blood_pressure_systolic=data.get('blood_pressure_systolic'),
                blood_pressure_diastolic=data.get('blood_pressure_diastolic'),
                oxygen_saturation=data.get('oxygen_saturation')
            )
            db.session.add(new_vitals)
            db.session.commit()
            return jsonify(new_vitals.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            return jsonify(error=str(e)), 500

    # GET Request
    try:
        # Query logs associated with the incident, order by timestamp descending
        vitals = PatientVitalsLog.query.filter_by(incident_id=incident_id).order_by(PatientVitalsLog.timestamp.desc()).all()
        results = [v.to_dict() for v in vitals]
        return jsonify(results), 200
    except Exception as e:
        return jsonify(error=str(e)), 500

## -- Staff API Routes -- ##

@app.route('/api/staff', methods=['GET', 'POST'])
def handle_staff():
    if request.method == 'POST':
        data = request.get_json()
        if not data or 'user_id' not in data:
            return jsonify(error="Missing user_id"), 400

        # Check if user exists before trying to add them as staff
        User.query.get_or_404(data['user_id'])
        # Optionally check if ambulance exists if assigned_ambulance_id is provided
        if data.get('assigned_ambulance_id'):
            Ambulance.query.get_or_404(data['assigned_ambulance_id'])

        new_staff = Staff(
            user_id=data['user_id'],
            certification_level=data.get('certification_level'),
            assigned_ambulance_id=data.get('assigned_ambulance_id')
        )
        try:
            db.session.add(new_staff)
            db.session.commit()
            return jsonify(new_staff.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            # Handle potential unique constraint violation on user_id gracefully
            error_str = str(e)
            if 'unique constraint' in error_str.lower() and 'user_id' in error_str.lower():
                return jsonify(error=f"User ID {data['user_id']} is already assigned to staff."), 409 # Conflict
            return jsonify(error=error_str), 500

    # GET Request
    try:
        staff_list = Staff.query.all()
        return jsonify([s.to_dict() for s in staff_list]), 200
    except Exception as e:
         return jsonify(error=str(e)), 500


# Basic route to get/update/delete a specific staff member
@app.route('/api/staff/<int:staff_id>', methods=['GET', 'PUT', 'DELETE'])
def handle_single_staff(staff_id):
    staff_member = Staff.query.get_or_404(staff_id)

    if request.method == 'GET':
        return jsonify(staff_member.to_dict())

    if request.method == 'PUT':
        data = request.get_json()
        try:
            staff_member.certification_level = data.get('certification_level', staff_member.certification_level)
            # Optionally check if ambulance exists before assigning
            assigned_ambulance_id = data.get('assigned_ambulance_id')
            if assigned_ambulance_id:
                Ambulance.query.get_or_404(assigned_ambulance_id)
            staff_member.assigned_ambulance_id = assigned_ambulance_id

            db.session.commit()
            return jsonify(staff_member.to_dict())
        except Exception as e:
            db.session.rollback()
            return jsonify(error=str(e)), 500

    if request.method == 'DELETE':
        try:
            db.session.delete(staff_member)
            db.session.commit()
            return '', 204
        except Exception as e:
            db.session.rollback()
            return jsonify(error=str(e)), 500


## -- Ambulance Equipment API Routes -- ##

@app.route('/api/ambulances/<int:ambulance_id>/equipment', methods=['GET', 'POST'])
def handle_ambulance_equipment(ambulance_id):
    # Check if ambulance exists first
    Ambulance.query.get_or_404(ambulance_id)

    if request.method == 'POST':
        data = request.get_json()
        if not data or 'equipment_name' not in data:
            return jsonify(error="Missing equipment_name"), 400

        new_equipment = Equipment(
            ambulance_id=ambulance_id,
            equipment_name=data['equipment_name'],
            status=data.get('status', 'operational')
        )
        try:
            db.session.add(new_equipment)
            db.session.commit()
            return jsonify(new_equipment.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            return jsonify(error=str(e)), 500

    # GET Request
    try:
        equipment_list = Equipment.query.filter_by(ambulance_id=ambulance_id).all()
        return jsonify([e.to_dict() for e in equipment_list]), 200
    except Exception as e:
        return jsonify(error=str(e)), 500


## -- Hospital Specialties API Routes -- ##

@app.route('/api/hospitals/<int:hospital_id>/specialties', methods=['GET', 'POST'])
def handle_hospital_specialties(hospital_id):
    # Check if hospital exists first
    Hospital.query.get_or_404(hospital_id)

    if request.method == 'POST':
        data = request.get_json()
        if not data or 'specialty_name' not in data:
            return jsonify(error="Missing specialty_name"), 400

        new_specialty = HospitalSpecialties(
            hospital_id=hospital_id,
            specialty_name=data['specialty_name'],
            is_available=data.get('is_available', True)
        )
        try:
            db.session.add(new_specialty)
            db.session.commit()
            return jsonify(new_specialty.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            return jsonify(error=str(e)), 500

    # GET Request
    try:
        specialties_list = HospitalSpecialties.query.filter_by(hospital_id=hospital_id).all()
        return jsonify([s.to_dict() for s in specialties_list]), 200
    except Exception as e:
         return jsonify(error=str(e)), 500


if __name__ == '__main__':
    app.run(debug=True)
