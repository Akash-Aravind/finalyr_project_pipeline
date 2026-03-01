# V2V DDoS Detection Dashboard Documentation

## Installation
1. **Clone the repository:**  
   ```bash
   git clone https://github.com/Akash-Aravind/finalyr_project_pipeline.git
   cd finalyr_project_pipeline
   ```

2. **Install the required packages:**  
   Ensure you have Python 3.7 or later, then run:  
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application:**  
   ```bash
   python app.py
   ```

## Features
- Real-time DDoS detection and visualization  
- Alerts and notifications for detected attacks  
- Historical data analysis  
- User-friendly dashboard with customizable views  
- Integration with third-party monitoring systems

## Default Credentials
- **Username:** admin  
- **Password:** password123  

> _Note: Change the default credentials after first login for security reasons._

## API Endpoints
| Method  | Endpoint                          | Description                             |
|---------|-----------------------------------|-----------------------------------------|
| GET     | /api/v1/status                    | Get the status of the dashboard         |
| POST    | /api/v1/detect                    | Send data for DDoS detection            |
| GET     | /api/v1/logs                      | Retrieve logs of detected events         |
| POST    | /api/v1/alerts                    | Send alert notifications                 |
| GET     | /api/v1/analytics                 | Fetch analytics over time                |

Please refer to the documentation of each endpoint for request and response formats.