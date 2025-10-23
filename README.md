# **Emergency Response System**

## **1\. Project Overview**

This project is a complete, full-stack emergency response system designed to provide real-time data from the field directly to dispatchers and hospitals. It consists of three main components:

1. **A Relational Database (MySQL):** A schema of 11 tables to store and relate all system data.  
2. **A Backend API (Python & Flask):** A robust REST API that serves as the "brain," handling all business logic, data queries, and connections.  
3. **A Frontend Dashboard (HTML & TailwindCSS):** A user-friendly, responsive web interface for dispatchers to monitor incidents, view available units, and log new emergencies.

The core "niche" of this project is its ability to simulate an IoT data stream, allowing ambulances to post live patient vitals (heart rate, O2 sat) to an incident, which can then be viewed by the receiving hospital.

## **2\. Key Features**

* **Full CRUD Functionality:** Secure API endpoints to create, read, update, and delete all core entities: Ambulances, Hospitals, Incidents, and Staff.  
* **Relational Data Integrity:** Uses foreign keys to ensure incidents are correctly linked to valid patients, ambulances, and hospitals.  
* **Real-Time Vitals Monitoring:** A dedicated endpoint (/api/incidents/\<id\>/vitals) allows an "ambulance" to POST live patient data, which can be retrieved by a hospital dashboard.  
* **Dynamic Frontend:** The dispatcher dashboard is built without a framework, using vanilla JavaScript's fetch API to read data from the backend and dynamically create UI elements.  
* **Scalable Structure:** The project is organized professionally with separate backend, frontend, and documentation folders.

## **3\. Technologies Used**

* **Backend:**  
  * **Language:** Python 3.10+  
  * **Framework:** Flask & Flask-SQLAlchemy  
  * **Database:** MySQL (connected via mysql-connector-python)  
  * **API Testing:** Postman  
  * **CORS Handling:** flask-cors  
* **Frontend:**  
  * **Markup:** HTML5  
  * **Styling:** Tailwind CSS (via CDN)  
  * **Logic:** Vanilla JavaScript (ES6+)  
  * **Icons:** Ionicons  
* **Database Design:**  
  * MySQL Workbench  
  * Mermaid (for ER Diagram)

## **4\. Project Structure**

The repository is organized at the root level for clarity.

/dms-mini-proj/  
|  
|-- 📂 aether-ems/  
|   |-- 📂 backend/  
|   |   |-- 📂 venv/  
|   |   |-- config.py         \# Database connection and secret keys  
|   |   \`-- run.py            \# The main Flask API application (all 11 models and 20+ routes)  
|   |  
|   \`-- 📂 frontend/  
|       \`-- index.html        \# The single-page dispatcher dashboard  
|  
|-- 📄 .gitignore            \# Ignores venv, pycache, and config.py  
|-- 📄 documentation.md      \# The Mermaid ER Diagram  
|-- 📄 README.md             \# This file  
\`-- 📄 SCHEMA.md             \# The detailed database schema

## **5\. Core API Endpoints**

This is a summary of the main API routes available.

| Method | Endpoint | Description |
| :---- | :---- | :---- |
| GET, POST | /api/ambulances | Get all ambulances or create a new one. |
| GET, PUT, DELETE | /api/ambulances/\<id\> | Get, update, or delete a single ambulance. |
| GET, POST | /api/hospitals | Get all hospitals or create a new one. |
| GET, PUT, DELETE | /api/hospitals/\<id\> | Get, update, or delete a single hospital. |
| GET, POST | /api/incidents | Get all incidents or create a new one. |
| GET, PUT | /api/incidents/\<id\> | Get or update a single incident (e.g., assign units). |
| GET, POST | /api/incidents/\<id\>/vitals | Get all vitals for an incident or post a new one (IoT). |
| GET, POST | /api/staff | Get all staff or create a new staff profile. |
| GET, POST | /api/ambulances/\<id\>/equipment | Get or add equipment for a specific ambulance. |
| GET, POST | /api/hospitals/\<id\>/specialties | Get or add specialties for a specific hospital. |

## **6\. Setup and Installation**

Follow these steps to run the project locally.

### **Prerequisites**

* Python 3.10+  
* MySQL Server (with a database named aether\_ems\_db created)  
* A tool to run SQL scripts (like MySQL Workbench)

### **1\. Clone the Repository**

git clone \[https://github.com/\](https://github.com/)\[Your-GitHub-Username\]/\[Your-Repo-Name\].git  
cd \[Your-Repo-Name\]

### **2\. Setup the Database**

1. Open MySQL Workbench.  
2. Create a new schema named aether\_ems\_db.  
3. Open and run the schema.sql script (from the project's database folder, if you create one, or from your documentation.md) to create all 11 tables.

### **3\. Setup the Backend**

1. Navigate to the backend folder:  
   cd aether-ems/backend

2. Create and activate a virtual environment:  
   python \-m venv venv  
   \# Windows  
   .\\venv\\Scripts\\Activate.ps1  
   \# macOS/Linux  
   source venv/bin/activate

3. Install the required libraries:  
   pip install Flask flask-sqlalchemy mysql-connector-python flask-cors

4. **Configure the database:**  
   * Rename config.py.example to config.py.  
   * Edit config.py and enter your MySQL USERNAME and PASSWORD.  
5. Run the server:  
   python run.py

   The API will now be running at http://127.0.0.1:5000.

### **4\. Run the Frontend**

1. Navigate to the frontend folder:  
   cd aether-ems/frontend

2. Open the index.html file directly in your web browser.

The dashboard will load, connect to your running backend, and be fully operational.
