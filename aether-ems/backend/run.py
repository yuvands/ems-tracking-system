from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
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
            'latitude': str(self.latitude),
            'longitude': str(self.longitude),
            'er_capacity': self.er_capacity,
            'er_current_occupancy': self.er_current_occupancy
        }

# ... (all your other models are here) ...

# --- ADD THIS NEW MODEL ---
# ... (all your other models are here) ...

# --- ADD THIS NEW MODEL ---
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
    
    # Default to GET
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

    # Default to GET
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
            db.session.delete(hospital)
            db.session.commit()
            return '', 204
        except Exception as e:
            db.session.rollback()
            return jsonify(error=str(e)), 500

@app.route('/api/incidents', methods=['POST'])
def create_incident():
    """Endpoint to create a new patient and incident."""
    data = request.get_json()
    if not data or 'location_lat' not in data or 'location_lon' not in data:
        return jsonify(error="Missing required location data"), 400

    try:
        # Step 1: Create a new patient with the info provided (can be anonymous)
        new_patient = Patient(
            full_name=data.get('patient_name'),
            dob=data.get('patient_dob'),
            blood_type=data.get('patient_blood_type')
        )
        db.session.add(new_patient)
        # We flush to get the new_patient.patient_id before committing
        db.session.flush()

        # Step 2: Create the incident and link it to the new patient
        new_incident = Incident(
            patient_id=new_patient.patient_id,
            location_lat=data['location_lat'],
            location_lon=data['location_lon'],
            location_description=data.get('description'),
            # For now, we'll manually assign these IDs
            dispatcher_id=data.get('dispatcher_id'),
            ambulance_id=data.get('ambulance_id'),
            destination_hospital_id=data.get('hospital_id')
        )
        db.session.add(new_incident)
        db.session.commit()
        
        return jsonify(new_incident.to_dict()), 201

    except Exception as e:
        db.session.rollback()
        return jsonify(error=str(e)), 500

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

    def to_dict(self):
        return {
            'id': self.incident_id,
            'patient_id': self.patient_id,
            'dispatcher_id': self.dispatcher_id,
            'ambulance_id': self.ambulance_id,
            'destination_hospital_id': self.destination_hospital_id,
            'latitude': str(self.location_lat),
            'longitude': str(self.location_lon),
            'description': self.location_description,
            'incident_time': self.incident_time.isoformat(),
            'status': self.status
        }

if __name__ == '__main__':
    app.run(debug=True)