# print_db_content.py

# This script connects to your MySQL database and prints the content of all tables.

# IMPORTANT: Please fill in your MySQL username and password below.

from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker
from run import User, Staff, Ambulance, Equipment, Hospital, HospitalSpecialties, Patient, Incident, PatientVitalsLog, Message

# --- Database Configuration ---
# Replace 'USERNAME' and 'PASSWORD' with your MySQL credentials.
DATABASE_URI = 'mysql+mysqlconnector://root:$8Herokite@localhost/aether_ems_db'

# --- Model Mapping ---
# Map table names to their corresponding SQLAlchemy model classes.
MODEL_MAPPING = {
    'users': User,
    'staff': Staff,
    'ambulances': Ambulance,
    'equipment': Equipment,
    'hospitals': Hospital,
    'hospital_specialties': HospitalSpecialties,
    'patients': Patient,
    'incidents': Incident,
    'patient_vitals_log': PatientVitalsLog,
    'messages': Message,
}

# --- Script ---
def print_table_content():
    """
    Connects to the database, queries all tables, and prints their content.
    """
    try:
        engine = create_engine(DATABASE_URI)
        Session = sessionmaker(bind=engine)
        session = Session()

        inspector = inspect(engine)
        table_names = inspector.get_table_names()

        print("--- Database Content ---")

        for table_name in table_names:
            print(f"\n--- Table: {table_name} ---")
            model_class = MODEL_MAPPING.get(table_name)
            if model_class:
                records = session.query(model_class).all()
                if not records:
                    print("No records found.")
                else:
                    for record in records:
                        # Assuming each model has a .to_dict() method for neat printing
                        if hasattr(record, 'to_dict'):
                            print(record.to_dict())
                        else:
                            print(record) # Fallback if to_dict() is not available
            else:
                print(f"Could not find a model class mapping for table '{table_name}'. Skipping.")

        session.close()

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == '__main__':
    print_table_content()