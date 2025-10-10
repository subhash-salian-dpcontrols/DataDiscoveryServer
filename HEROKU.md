# Heroku Deployment Guide

## Prerequisites

1. Install Heroku CLI
2. Have a Heroku account
3. Install Git

## Setup Steps

1. Login to Heroku CLI:
```bash
heroku login
```

2. Create a new Heroku app:
```bash
heroku create data-discovery-server
```

3. Add PostgreSQL addon:
```bash
heroku addons:create heroku-postgresql:mini
```

4. Set environment variables:
```bash
heroku config:set API_KEY=your-secure-api-key
```

5. Initialize Git (if not already done):
```bash
git init
git add .
git commit -m "Initial commit for Heroku deployment"
```

6. Push to Heroku:
```bash
git push heroku main
```

## Database Configuration

The application will automatically use the DATABASE_URL provided by Heroku's PostgreSQL addon. No manual configuration needed.

## Post-Deployment Steps

1. Create admin user:
```bash
heroku run python -c "from db import init_db, create_user; init_db(); create_user('Admin', 'Admin@123', 'admin')"
```

2. View your application:
```bash
heroku open
```

3. Check logs:
```bash
heroku logs --tail
```

## Monitoring and Maintenance

1. Monitor application:
```bash
# View application status
heroku ps

# Check resource usage
heroku ps:utilization

# View recent logs
heroku logs --tail
```

2. Database management:
```bash
# Access database console
heroku pg:psql

# View database info
heroku pg:info
```

## Scaling

If needed, you can scale your application:
```bash
# Scale web dynos
heroku ps:scale web=2

# Upgrade database plan
heroku addons:upgrade heroku-postgresql:standard-0
```

## Troubleshooting

1. If the application fails to start:
   ```bash
   heroku logs --tail
   ```

2. If database connection fails:
   ```bash
   # Verify database URL
   heroku config:get DATABASE_URL
   
   # Reset database connection
   heroku pg:reset DATABASE_URL
   ```

3. Restart the application:
   ```bash
   heroku restart
   ```

## Security Notes

1. Never commit sensitive information to Git
2. Use environment variables for all secrets
3. Regularly rotate API keys and passwords
4. Monitor application logs for unusual activity
5. Keep dependencies updated:
   ```bash
   pip freeze > requirements.txt
   git commit -am "Update dependencies"
   git push heroku main
   ```

## Useful Heroku Commands

```bash
# View app info
heroku apps:info

# View configuration
heroku config

# Add collaborators
heroku access:add user@example.com

# View release history
heroku releases

# Rollback to previous version if needed
heroku rollback
```