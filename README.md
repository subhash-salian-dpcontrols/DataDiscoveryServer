# Data Discovery Server

A FastAPI-based web application for managing and visualizing PII (Personally Identifiable Information) data detections across systems.

## Features

- User authentication and role-based access control
- Dashboard for visualizing PII detections
- REST API for uploading PII detection results
- PostgreSQL database backend
- Docker support for easy deployment

## Setup

1. Clone the repository:
```bash
git clone https://github.com/subhash-salian-dpcontrols/DataDiscoveryServer.git
cd DataDiscoveryServer
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up environment variables:
```bash
API_KEY=your_api_key
DATABASE_URL=postgresql://postgres:Submax@2206@localhost:5432/pii_data
```

4. Initialize the database:
```bash
python init_db.py
```

5. Run the server:
```bash
uvicorn DataDiscoveryServer:app --reload
```

## API Documentation

Access the API documentation at `http://localhost:8000/docs` after starting the server.

## Docker Support

Build and run with Docker Compose:
```bash
docker-compose up --build
```

## License

MIT