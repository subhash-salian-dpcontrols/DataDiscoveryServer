# Deployment Guide for Google Cloud Run

## Prerequisites

1. Install Google Cloud SDK
2. Have a Google Cloud Project
3. Enable required APIs:
   - Cloud Run API
   - Cloud SQL Admin API
   - Cloud Build API

## Setup Steps

1. Create a Cloud SQL PostgreSQL instance:
```bash
gcloud sql instances create pii-database \
    --database-version=POSTGRES_13 \
    --tier=db-f1-micro \
    --region=us-central1
```

2. Set a password for the postgres user:
```bash
gcloud sql users set-password postgres \
    --instance=pii-database \
    --password=your-secure-password
```

3. Create the database:
```bash
gcloud sql databases create pii_data --instance=pii-database
```

4. Update environment variables in cloudrun.yaml with your configuration:
   - POSTGRES_PASSWORD: Your database password
   - POSTGRES_HOST: Your Cloud SQL instance connection name
   - API_KEY: Your chosen API key

5. Build and deploy to Cloud Run:
```bash
# Authenticate with Google Cloud
gcloud auth login

# Set your project ID
gcloud config set project YOUR_PROJECT_ID

# Build and deploy
gcloud builds submit --tag gcr.io/YOUR_PROJECT_ID/data-discovery-server

gcloud run deploy data-discovery-server \
    --image gcr.io/YOUR_PROJECT_ID/data-discovery-server \
    --platform managed \
    --region us-central1 \
    --allow-unauthenticated \
    --add-cloudsql-instances YOUR_PROJECT_ID:us-central1:pii-database
```

## Post-Deployment

1. The service URL will be provided after deployment
2. Update your client applications to use the new endpoint
3. Make sure to include the API key in requests to the upload endpoint

## Monitoring

- View logs: `gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=data-discovery-server"`
- Monitor service: Visit Cloud Run dashboard in Google Cloud Console

## Security Notes

1. Use secure passwords and API keys
2. Consider implementing additional authentication
3. Regularly rotate credentials
4. Monitor access logs
5. Consider setting up Cloud Armor for additional protection