# **Aether-EMS: Database Schema Design**

This document details the database schema for the Aether-EMS project, including all tables, columns, data types, and constraints.

### **1\. users**

Stores all users who can log in, including dispatchers, paramedics, and hospital staff.

| Column Name | Data Type | Constraints | Notes |
| :---- | :---- | :---- | :---- |
| **user\_id** | INT | PRIMARY KEY, AUTO\_INCREMENT | Unique identifier for the user. |
| username | VARCHAR(50) | NOT NULL, UNIQUE | The user's login name. |
| password\_hash | VARCHAR(255) | NOT NULL | Stores the user's hashed password. |
| full\_name | VARCHAR(100) | NOT NULL | The user's full name. |
| role | ENUM(...) | NOT NULL | Role (e.g., 'admin', 'dispatcher', 'paramedic'). |
| created\_at | TIMESTAMP | DEFAULT CURRENT\_TIMESTAMP | When the user account was created. |

### **2\. ambulances**

Stores all ambulances, their live status, and location.

| Column Name | Data Type | Constraints | Notes |
| :---- | :---- | :---- | :---- |
| **ambulance\_id** | INT | PRIMARY KEY, AUTO\_INCREMENT | Unique identifier for the ambulance. |
| license\_plate | VARCHAR(20) | NOT NULL, UNIQUE | The vehicle's license plate. |
| status | ENUM(...) | NOT NULL | Live status (e.g., 'available', 'en\_route'). |
| current\_lat | DECIMAL(10, 8\) | NULLABLE | Live GPS latitude. |
| current\_lon | DECIMAL(11, 8\) | NULLABLE | Live GPS longitude. |
| last\_updated | TIMESTAMP | DEFAULT CURRENT\_TIMESTAMP | Automatically updates on change. |

### **3\. staff**

Links a user account to a paramedic/staff profile and assigns them to an ambulance.

| Column Name | Data Type | Constraints | Notes |
| :---- | :---- | :---- | :---- |
| **staff\_id** | INT | PRIMARY KEY, AUTO\_INCREMENT | Unique identifier for the staff member. |
| **user\_id** | INT | NOT NULL, UNIQUE, FOREIGN KEY (users.user\_id) | Links to the users table. |
| certification\_level | VARCHAR(50) | NULLABLE | e.g., 'EMT-P', 'Paramedic'. |
| **assigned\_ambulance\_id** | INT | NULLABLE, FOREIGN KEY (ambulances.ambulance\_id) | Which ambulance this staff is on. |

### **4\. hospitals**

Stores all registered hospitals, their locations, and ER capacity.

| Column Name | Data Type | Constraints | Notes |
| :---- | :---- | :---- | :---- |
| **hospital\_id** | INT | PRIMARY KEY, AUTO\_INCREMENT | Unique identifier for the hospital. |
| name | VARCHAR(100) | NOT NULL | The hospital's name. |
| address | VARCHAR(255) | NULLABLE | The hospital's physical address. |
| latitude | DECIMAL(10, 8\) | NOT NULL | GPS latitude for routing. |
| longitude | DECIMAL(11, 8\) | NOT NULL | GPS longitude for routing. |
| er\_capacity | INT | NULLABLE | Total number of ER beds. |
| er\_current\_occupancy | INT | NULLABLE | Current number of occupied ER beds. |

### **5\. hospital\_specialties**

A list of specialties (e.g., "Cardiology", "Trauma") available at a specific hospital.

| Column Name | Data Type | Constraints | Notes |
| :---- | :---- | :---- | :---- |
| **specialty\_id** | INT | PRIMARY KEY, AUTO\_INCREMENT | Unique identifier for the specialty record. |
| **hospital\_id** | INT | NOT NULL, FOREIGN KEY (hospitals.hospital\_id) | Links to the hospitals table. |
| specialty\_name | VARCHAR(100) | NOT NULL | e.g., 'Cardiology', 'Neurology'. |
| is\_available | BOOLEAN | DEFAULT TRUE | If this specialty is currently available. |

### **6\. equipment**

A list of medical equipment available on a specific ambulance.

| Column Name | Data Type | Constraints | Notes |
| :---- | :---- | :---- | :---- |
| **equipment\_id** | INT | PRIMARY KEY, AUTO\_INCREMENT | Unique identifier for the equipment item. |
| **ambulance\_id** | INT | NOT NULL, FOREIGN KEY (ambulances.ambulance\_id) | Links to the ambulances table. |
| equipment\_name | VARCHAR(100) | NOT NULL | e.g., 'Defibrillator', 'Ventilator'. |
| status | ENUM(...) | NOT NULL, DEFAULT 'operational' | 'operational' or 'maintenance\_required'. |

### **7\. patients**

Stores basic patient information. A new patient is created for each new incident.

| Column Name | Data Type | Constraints | Notes |
| :---- | :---- | :---- | :---- |
| **patient\_id** | INT | PRIMARY KEY, AUTO\_INCREMENT | Unique identifier for the patient. |
| full\_name | VARCHAR(100) | NULLABLE | Patient's name (if known). |
| dob | DATE | NULLABLE | Patient's date of birth (if known). |
| blood\_type | VARCHAR(5) | NULLABLE | e.g., 'O+', 'AB-'. |

### **8\. incidents**

The core table that links patients, dispatchers, ambulances, and hospitals for an emergency event.

| Column Name | Data Type | Constraints | Notes |
| :---- | :---- | :---- | :---- |
| **incident\_id** | INT | PRIMARY KEY, AUTO\_INCREMENT | Unique identifier for the incident. |
| **patient\_id** | INT | FOREIGN KEY (patients.patient\_id) | Links to the patients table. |
| **dispatcher\_id** | INT | FOREIGN KEY (users.user\_id) | Links to the users (dispatcher) table. |
| **ambulance\_id** | INT | FOREIGN KEY (ambulances.ambulance\_id) | Which ambulance is assigned. |
| **destination\_hospital\_id** | INT | FOREIGN KEY (hospitals.hospital\_id) | Which hospital is the destination. |
| location\_lat | DECIMAL(10, 8\) | NOT NULL | Incident's GPS latitude. |
| location\_lon | DECIMAL(11, 8\) | NOT NULL | Incident's GPS longitude. |
| location\_description | TEXT | NULLABLE | Dispatcher's notes on the scene. |
| status | ENUM(...) | NOT NULL, DEFAULT 'active' | 'active', 'closed', 'cancelled'. |
| incident\_time | TIMESTAMP | DEFAULT CURRENT\_TIMESTAMP | When the incident was logged. |

### **9\. patient\_vitals\_log**

The "IoT" table. Stores a time-series log of patient vitals streamed from the ambulance.

| Column Name | Data Type | Constraints | Notes |
| :---- | :---- | :---- | :---- |
| **log\_id** | BIGINT | PRIMARY KEY, AUTO\_INCREMENT | Unique identifier for the log entry. |
| **incident\_id** | INT | NOT NULL, FOREIGN KEY (incidents.incident\_id) | Links to the incidents table. |
| timestamp | TIMESTAMP | DEFAULT CURRENT\_TIMESTAMP | The exact time this vital was recorded. |
| heart\_rate | INT | NULLABLE | e.g., 85 (bpm). |
| blood\_pressure\_systolic | INT | NULLABLE | e.g., 120\. |
| blood\_pressure\_diastolic | INT | NULLABLE | e.g., 80\. |
| oxygen\_saturation | DECIMAL(5, 2\) | NULLABLE | e.g., 98.5 (%). |

### **10\. routes**

(For AI/ML feature) Stores the predicted route and ETA for an ambulance.

| Column Name | Data Type | Constraints | Notes |
| :---- | :---- | :---- | :---- |
| **route\_id** | INT | PRIMARY KEY, AUTO\_INCREMENT | Unique identifier for the route. |
| **incident\_id** | INT | NOT NULL, UNIQUE, FOREIGN KEY (incidents.incident\_id) | Links to the incidents table. |
| predicted\_eta | TIMESTAMP | NULLABLE | The AI-predicted arrival time. |
| actual\_arrival\_time | TIMESTAMP | NULLABLE | Logged on arrival for model retraining. |
| route\_path | JSON | NULLABLE | Stores a GeoJSON LineString of coordinates. |

### **11\. dispatch\_log**

An audit trail of all actions taken by a dispatcher for a specific incident.

| Column Name | Data Type | Constraints | Notes |
| :---- | :---- | :---- | :---- |
| **log\_id** | INT | PRIMARY KEY, AUTO\_INCREMENT | Unique identifier for the log entry. |
| **incident\_id** | INT | NOT NULL, FOREIGN KEY (incidents.incident\_id) | Links to the incidents table. |
| **user\_id** | INT | NULLABLE, FOREIGN KEY (users.user\_id) | Which dispatcher took the action. |
| action | VARCHAR(255) | NULLABLE | e.g., 'Incident Created', 'Ambulance Dispatched'. |
| timestamp | TIMESTAMP | DEFAULT CURRENT\_TIMESTAMP | When the action was logged. |

