# **SQL Queries** 

## **1\. Database Creation**

CREATE DATABASE IF NOT EXISTS aether\_ems\_db;  
USE aether\_ems\_db;

## **2\. Full Database Schema** 

CREATE TABLE users (  
    user\_id INT AUTO\_INCREMENT PRIMARY KEY,  
    username VARCHAR(50) NOT NULL UNIQUE,  
    password\_hash VARCHAR(255) NOT NULL,  
    full\_name VARCHAR(100) NOT NULL,  
    role ENUM('admin', 'dispatcher', 'paramedic', 'hospital\_staff') NOT NULL,  
    created\_at TIMESTAMP DEFAULT CURRENT\_TIMESTAMP  
);

CREATE TABLE ambulances (  
    ambulance\_id INT AUTO\_INCREMENT PRIMARY KEY,  
    license\_plate VARCHAR(20) NOT NULL UNIQUE,  
    status ENUM('available', 'en\_route\_to\_scene', 'at\_scene', 'en\_route\_to\_hospital', 'unavailable') NOT NULL DEFAULT 'unavailable',  
    current\_lat DECIMAL(10, 8),  
    current\_lon DECIMAL(11, 8),  
    last\_updated TIMESTAMP DEFAULT CURRENT\_TIMESTAMP ON UPDATE CURRENT\_TIMESTAMP  
);

CREATE TABLE staff (  
    staff\_id INT AUTO\_INCREMENT PRIMARY KEY,  
    user\_id INT NOT NULL UNIQUE,  
    certification\_level VARCHAR(50),  
    assigned\_ambulance\_id INT,  
    FOREIGN KEY (user\_id) REFERENCES users(user\_id) ON DELETE CASCADE,  
    FOREIGN KEY (assigned\_ambulance\_id) REFERENCES ambulances(ambulance\_id) ON DELETE SET NULL  
);

CREATE TABLE hospitals (  
    hospital\_id INT AUTO\_INCREMENT PRIMARY KEY,  
    name VARCHAR(100) NOT NULL,  
    address VARCHAR(255),  
    latitude DECIMAL(10, 8\) NOT NULL,  
    longitude DECIMAL(11, 8\) NOT NULL,  
    er\_capacity INT,  
    er\_current\_occupancy INT  
);

CREATE TABLE hospital\_specialties (  
    specialty\_id INT AUTO\_INCREMENT PRIMARY KEY,  
    hospital\_id INT NOT NULL,  
    specialty\_name VARCHAR(100) NOT NULL,  
    is\_available BOOLEAN DEFAULT TRUE,  
    FOREIGN KEY (hospital\_id) REFERENCES hospitals(hospital\_id) ON DELETE CASCADE  
);

CREATE TABLE equipment (  
    equipment\_id INT AUTO\_INCREMENT PRIMARY KEY,  
    ambulance\_id INT NOT NULL,  
    equipment\_name VARCHAR(100) NOT NULL,  
    status ENUM('operational', 'maintenance\_required') NOT NULL DEFAULT 'operational',  
    FOREIGN KEY (ambulance\_id) REFERENCES ambulances(ambulance\_id) ON DELETE CASCADE  
);

CREATE TABLE patients (  
    patient\_id INT AUTO\_INCREMENT PRIMARY KEY,  
    full\_name VARCHAR(100),  
    dob DATE,  
    blood\_type VARCHAR(5)  
);

CREATE TABLE incidents (  
    incident\_id INT AUTO\_INCREMENT PRIMARY KEY,  
    patient\_id INT,  
    dispatcher\_id INT,  
    ambulance\_id INT,  
    destination\_hospital\_id INT,  
    location\_description TEXT,  
    location\_lat DECIMAL(10, 8\) NOT NULL,  
    location\_lon DECIMAL(11, 8\) NOT NULL,  
    incident\_time TIMESTAMP DEFAULT CURRENT\_TIMESTAMP,  
    status ENUM('active', 'closed', 'cancelled') NOT NULL DEFAULT 'active',  
    FOREIGN KEY (patient\_id) REFERENCES patients(patient\_id) ON DELETE RESTRICT,  
    FOREIGN KEY (dispatcher\_id) REFERENCES users(user\_id) ON DELETE SET NULL,  
    FOREIGN KEY (ambulance\_id) REFERENCES ambulances(ambulance\_id) ON DELETE SET NULL,  
    FOREIGN KEY (destination\_hospital\_id) REFERENCES hospitals(hospital\_id) ON DELETE SET NULL  
);

CREATE TABLE routes (  
    route\_id INT AUTO\_INCREMENT PRIMARY KEY,  
    incident\_id INT NOT NULL UNIQUE,  
    predicted\_eta TIMESTAMP,  
    actual\_arrival\_time TIMESTAMP,  
    route\_path JSON, \-- Stores a GeoJSON LineString or a series of coordinates  
    FOREIGN KEY (incident\_id) REFERENCES incidents(incident\_id) ON DELETE CASCADE  
);

CREATE TABLE patient\_vitals\_log (  
    log\_id BIGINT AUTO\_INCREMENT PRIMARY KEY,  
    incident\_id INT NOT NULL,  
    timestamp TIMESTAMP DEFAULT CURRENT\_TIMESTAMP,  
    heart\_rate INT,  
    blood\_pressure\_systolic INT,  
    blood\_pressure\_diastolic INT,  
    oxygen\_saturation DECIMAL(5, 2),  
    FOREIGN KEY (incident\_id) REFERENCES incidents(incident\_id) ON DELETE CASCADE  
);

CREATE TABLE dispatch\_log (  
    log\_id INT AUTO\_INCREMENT PRIMARY KEY,  
    incident\_id INT NOT NULL,  
    user\_id INT,  
    action VARCHAR(255),  
    timestamp TIMESTAMP DEFAULT CURRENT\_TIMESTAMP,  
    FOREIGN KEY (incident\_id) REFERENCES incidents(incident\_id) ON DELETE CASCADE,  
    FOREIGN KEY (user\_id) REFERENCES users(user\_id) ON DELETE SET NULL  
);

## **3\. Schema Modification** 

ALTER TABLE ambulances MODIFY COLUMN status   
ENUM('available', 'en\_route\_to\_scene', 'at\_scene', 'en\_route\_to\_hospital', 'unavailable', 'maintenance\_required')   
NOT NULL DEFAULT 'unavailable';

## **4\. Test Data Insertion** 

USE aether\_ems\_db;  
INSERT INTO users (username, password\_hash, full\_name, role)   
VALUES ('dispatch1', 'some\_secure\_password\_hash', 'Main Dispatcher', 'dispatcher');

INSERT INTO users (username, password\_hash, full\_name, role)   
VALUES ('paramedic1', 'some\_hash', 'Jane Doe', 'paramedic');  
