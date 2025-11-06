# **Emergency Management System (EMS)**

## **1. Project Overview**

This project is a complete, full-stack emergency response system designed to provide real-time data from the field directly to dispatchers and hospitals. It consists of three main components:

1.  **A Relational Database (MySQL):** A schema of 10 tables to store and relate all system data, managed via SQLAlchemy models.
2.  **A Backend API (Python & Flask):** A robust REST API that serves as the "brain," handling all business logic, data queries, and real-time communication via WebSockets.
3.  **A Frontend Dashboard (HTML & TailwindCSS):** A user-friendly, responsive web interface for dispatchers to monitor incidents, view available units, and log new emergencies in real-time.

The core "niche" of this project is its ability to simulate an IoT data stream, allowing ambulances to post live patient vitals (heart rate, O2 sat) to an incident, which can then be viewed by the receiving hospital. The system also features live chat for incident coordination and automated dispatch suggestions.

## **2. Key Features**

*   **Role-Based Access Control (RBAC):** Secure authentication using JWT, with distinct roles (Supervisor, Dispatcher, Paramedic, Hospital Staff) governing API access.
*   **Full CRUD Functionality:** Endpoints to create, read, update, and delete all core entities: Users, Ambulances, Hospitals, Incidents, and Staff.
*   **Real-Time Dashboard:** The frontend updates dynamically without page reloads, thanks to **Flask-SocketIO**, which pushes updates for ambulances, incidents, and hospitals.
*   **Live Incident Chat:** A dedicated chat room for each incident, allowing paramedics, dispatchers, and hospital staff to communicate seamlessly.
*   **Real-Time Vitals Monitoring:** A dedicated endpoint and socket event for streaming live patient data from an ambulance to hospital and dispatcher dashboards.
*   **Automated Dispatch Suggestions:** An API endpoint that suggests the nearest available ambulance based on location and (optionally) required equipment.
*   **Dynamic Frontend:** The dispatcher dashboard is built without a framework, using vanilla JavaScript's `fetch` API and the `socket.io-client` to interact with the backend.
*   **Database Seeding:** A simple endpoint to populate the database with initial sample data for hospitals and ambulances in the Manipal, India region.

## **3. Security Features**

Security is a core consideration in this project. The following features have been implemented to protect the application and its data:

*   **Password Hashing:** User passwords are never stored in plaintext. They are hashed using **Bcrypt** before being saved to the database, providing strong protection against database breaches.

*   **JWT-Based Authentication:** All protected API endpoints require a valid JSON Web Token (JWT), which is generated upon successful login. This ensures that only authenticated users can access system resources.

*   **Role-Based Access Control (RBAC):** The system implements a granular RBAC mechanism using a custom decorator (`@roles_required`).
    *   User roles (e.g., `supervisor`, `dispatcher`, `paramedic`) are embedded within the JWT claims.
    *   API endpoints are protected based on these roles, ensuring users can only perform actions appropriate for their permission level (e.g., only a `supervisor` can delete a hospital).
    *   Additional checks are performed within endpoints for resource ownership (e.g., a paramedic can only update the status of their *assigned* ambulance).

*   **Input Validation:** Data is validated at the model level using SQLAlchemy's validation decorators. This prevents malformed or invalid data (e.g., incorrect status enums) from being saved to the database, protecting against data integrity issues.

*   **Secure Configuration:** Sensitive information like the application's `SECRET_KEY` and database credentials are kept separate from the codebase in a `config.py` file, which is explicitly ignored by version control (`.gitignore`) to prevent accidental exposure.

*   **CORS Protection:** Cross-Origin Resource Sharing (CORS) is managed by **Flask-Cors**, limiting API access to designated origins. While currently configured permissively for development, it can be easily locked down to a specific frontend domain in a production environment.

## **4. Technologies Used**

*   **Backend:**
    *   **Language:** Python 3.10+
    *   **Framework:** Flask, Flask-SQLAlchemy, Flask-SocketIO
    *   **Authentication:** Flask-Bcrypt, Flask-JWT-Extended
    *   **Database:** MySQL (via `mysql-connector-python`)
    *   **CORS Handling:** Flask-Cors
    *   **WSGI Server:** Eventlet
*   **Frontend:**
    *   **Markup:** HTML5
    *   **Styling:** Tailwind CSS (via CDN)
    *   **Logic:** Vanilla JavaScript (ES6+)
    *   **Real-Time:** Socket.IO Client
    *   **Icons:** Ionicons
*   **Database Design:**
    *   MySQL Workbench
    *   Mermaid (for ER Diagram)

## **5. Project Structure**

The repository is organized for clarity and separation of concerns.

```
/dms-mini-proj/
|
|-- 📂 ems/
|   |-- 📂 backend/
|   |   |-- 📂 venv/
|   |   |-- run.py            # The main Flask API & SocketIO application
|   |   `-- sample-config.py  # Example configuration for the database
|   |
|   |-- 📂 frontend/
|   |   `-- index.html        # The single-page dispatcher dashboard
|   |
|   |-- documentation.md      # Mermaid ER Diagram
|   |-- schema.md             # Detailed database schema description
|   `-- sql-queries.md        # Sample SQL queries
|
|-- .gitignore
`-- README.md             # This file
```

## **6. Core API Endpoints**

This is a summary of the main API routes available. Access is restricted by roles.

| Method           | Endpoint                                    | Description                                                 |
| :--------------- | :------------------------------------------ | :---------------------------------------------------------- |
| **Auth**         |                                             |                                                             |
| POST             | `/api/register`                             | Register a new user.                                        |
| POST             | `/api/login`                                | Log in to get a JWT access token.                           |
| **Users**        |                                             | *(Supervisor only)*                                         |
| GET              | `/api/users`                                | Get a list of all users.                                    |
| GET, PUT, DELETE | `/api/users/<id>`                           | Get, update, or delete a specific user.                     |
| **Ambulances**   |                                             |                                                             |
| GET, POST        | `/api/ambulances`                           | Get all ambulances or create a new one.                     |
| GET, PUT, DELETE | `/api/ambulances/<id>`                      | Get, update, or delete a single ambulance.                  |
| **Hospitals**    |                                             |                                                             |
| GET, POST        | `/api/hospitals`                            | Get all hospitals or create a new one.                      |
| GET, PUT, DELETE | `/api/hospitals/<id>`                       | Get, update, or delete a single hospital.                   |
| **Incidents**    |                                             |                                                             |
| GET, POST        | `/api/incidents`                            | Get all incidents or create a new one.                      |
| GET, PUT, DELETE | `/api/incidents/<id>`                       | Get, update, or delete a single incident.                   |
| GET, POST        | `/api/incidents/<id>/vitals`                | Get vitals for an incident or post a new one.               |
| GET, POST        | `/api/incidents/<id>/messages`              | Get chat messages for an incident or post a new one.        |
| **Staff**        |                                             | *(Supervisor only)*                                         |
| GET, POST        | `/api/staff`                                | Get all staff profiles or create a new one.                 |
| GET, PUT, DELETE | `/api/staff/<id>`                           | Get, update, or delete a specific staff profile.            |
| **Equipment**    |                                             |                                                             |
| GET, POST        | `/api/ambulances/<id>/equipment`            | Get or add equipment for a specific ambulance.              |
| PUT, DELETE      | `/api/equipment/<id>`                       | Update or delete a specific piece of equipment.             |
| **Specialties**  |                                             |                                                             |
| GET, POST        | `/api/hospitals/<id>/specialties`           | Get or add specialties for a specific hospital.             |
| PUT, DELETE      | `/api/specialties/<id>`                     | Update or delete a specific hospital specialty.             |
| **Dispatch**     |                                             |                                                             |
| POST             | `/api/dispatch/suggest`                     | Suggests the best ambulance for a new incident.             |
| **Admin**        |                                             |                                                             |
| POST             | `/api/seed-manipal-data`                    | Seeds the database with sample hospitals and ambulances.    |

## **7. Real-Time Functionality (WebSockets)**

The application uses Flask-SocketIO for real-time communication between the server and clients.

*   **Global Updates (`dashboard_updates` room):**
    *   `ambulance_update`, `ambulance_deleted`
    *   `hospital_update`, `hospital_deleted`
    *   `incident_update`, `incident_deleted`
    *   `vitals_update` (for general dashboard alerts)
    *   `incident_message` (for general dashboard alerts)
*   **Incident-Specific Updates (`incident_<id>` room):**
    *   `vitals_update`: A new vitals log was posted for this incident.
    *   `incident_message`: A new chat message was posted for this incident.

Clients join rooms upon connection and when viewing a specific incident to receive targeted updates.

## **8. Live Map and Geolocation**

The dashboard features a live, interactive map that provides a real-time geospatial overview of all system assets and active incidents.

*   **Technology:** The map is built using the open-source **Leaflet.js** library, with map tiles provided by **OpenStreetMap**.

*   **Functionality:**
    *   **Visualizes Key Entities:** The map displays markers for all active incidents, ambulances, and hospitals that have location data.
    *   **Status-Based Markers:** Ambulance markers are color-coded to provide an at-a-glance understanding of their current status:
        *   **Green:** Available
        *   **Blue:** En route or at a scene
        *   **Gray:** Unavailable
    *   **Custom Icons:** Incidents (red) and hospitals (purple) also have distinct markers.
    *   **Interactive Popups:** Clicking on any marker reveals a popup with key information, such as an incident's status, an ambulance's license plate, or a hospital's name and ER capacity.

*   **Real-Time Updates:** The map is populated with data on initial page load and is then updated in real-time via the WebSocket connection. Any change in an ambulance's location or status, or the creation of a new incident, is immediately reflected on the map without needing a page refresh.

## **9. Setup and Installation**

Follow these steps to run the project locally.

### **Prerequisites**

*   Python 3.10+
*   MySQL Server (or another compatible database)

### **1. Clone the Repository**

```bash
git clone https://github.com/[Your-GitHub-Username]/[Your-Repo-Name].git
cd [Your-Repo-Name]
```

### **2. Setup the Database**

1.  Ensure your MySQL server is running.
2.  Create a new schema (database) named `aether_ems_db`.
    ```sql
    CREATE DATABASE aether_ems_db;
    ```
3.  The tables will be created automatically by the backend on startup.

### **3. Setup the Backend**

1.  Navigate to the backend folder:
    ```bash
    cd ems/backend
    ```

2.  Create and activate a virtual environment:
    ```bash
    # Create the environment
    python -m venv venv

    # Activate on Windows (PowerShell)
    .\venv\Scripts\Activate.ps1

    # Activate on macOS/Linux
    source venv/bin/activate
    ```

3.  Install the required libraries:
    ```bash
    pip install Flask Flask-SQLAlchemy mysql-connector-python Flask-Cors Flask-Bcrypt Flask-JWT-Extended Flask-SocketIO eventlet
    ```

4.  **Configure the database:**
    *   Create a new file named `config.py` in the `ems/backend` directory.
    *   Copy the contents from `sample-config.py` into `config.py`.
    *   Edit `config.py` and enter your MySQL **USERNAME** and **PASSWORD**.

5.  Run the server:
    ```bash
    python run.py
    ```

    The API and WebSocket server will now be running at `http://127.0.0.1:5000`.

### **4. Run the Frontend**

1.  Navigate to the frontend folder:
    ```bash
    cd ems/frontend
    ```
    *(Note: You can do this in a separate terminal)*

2.  Open the `index.html` file directly in your web browser.

The dashboard will load, connect to your running backend, and be fully operational.

### **5. Seeding Initial Data (Optional)**

After logging in as a user with the `supervisor` role, you can send a POST request to the `/api/seed-manipal-data` endpoint (e.g., using Postman or `curl`) to populate the database with sample hospitals and ambulances.

