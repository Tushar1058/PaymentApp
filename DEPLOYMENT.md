# Deployment Guide for Railway.app

## Advantages of Railway
- Simple GitHub-based deployment
- 500 hours/month free tier
- No sleep time
- Automatic HTTPS
- $5 credit free monthly
- Easy database integration
- Automatic deployments
- Built-in monitoring

## Prerequisites
1. GitHub account
2. Your code pushed to a GitHub repository
3. Railway.app account (sign up with GitHub)

## Deployment Steps

### 1. Prepare Your Repository

1. Ensure your repository has these files:
   - `requirements.txt`
   - `Procfile` (create this file with content):
     ```
     web: gunicorn app:app
     ```
   - `.env` (for local development only)

2. Update your `app.py` to use environment variables:
   ```python
   # Add at the top of app.py
   import os
   from dotenv import load_dotenv
   load_dotenv()  # This will load .env in development

   # Update database configuration
   db_path = os.getenv('DATABASE_URL', 'sqlite:///database/wallet.db')
   app.config['SQLALCHEMY_DATABASE_URI'] = db_path
   ```

### 2. Deploy on Railway

1. Go to [Railway.app](https://railway.app/)
2. Click "Start a New Project"
3. Choose "Deploy from GitHub repo"
4. Select your repository
5. Railway will automatically:
   - Detect your Python project
   - Install dependencies
   - Start your application

### 3. Configure Environment Variables

1. In your Railway project dashboard:
2. Go to "Variables" tab
3. Add these variables:
   ```
   FLASK_APP=app.py
   FLASK_ENV=production
   SECRET_KEY=your-secure-secret-key
   DATABASE_URL=sqlite:///app/database/wallet.db
   ```

### 4. Set Up Persistent Storage

1. In your Railway project:
2. Go to "Volumes" tab
3. Create a new volume
4. Mount it to `/app/database`
   - This ensures your database persists between deployments
   - Static files will be handled by the application

### 5. Domain Setup

1. Go to "Settings" tab
2. You'll find your generated domain (yourapp.railway.app)
3. Optional: Add custom domain
   - Click "Custom Domain"
   - Follow the DNS setup instructions

## Monitoring and Maintenance

### View Logs
1. Go to "Deployments" tab
2. Click on current deployment
3. View real-time logs

### Monitor Usage
1. Check "Metrics" tab for:
   - CPU usage
   - Memory usage
   - Disk usage
   - Network traffic

### Update Application
1. Simply push to your GitHub repository
2. Railway automatically deploys updates

### Database Backups
1. Use Railway's built-in backup system:
   - Go to "Volumes" tab
   - Click "Create Backup"
   - Download backup files

## Best Practices

1. **Environment Variables**
   - Never commit `.env` file
   - Use Railway's variable manager

2. **Monitoring**
   - Regularly check logs
   - Set up notifications

3. **Updates**
   - Test locally before pushing
   - Use feature branches

4. **Security**
   - Keep dependencies updated
   - Use secure environment variables

## Troubleshooting

1. **Deployment Failed**
   - Check build logs
   - Verify requirements.txt
   - Check Procfile format

2. **Application Errors**
   - Check application logs
   - Verify environment variables
   - Check volume mounts

3. **Performance Issues**
   - Monitor resource usage
   - Check database queries
   - Review application logs

## Cost Management

1. Monitor usage to stay within free tier:
   - 500 hours/month
   - $5 credit limit
   - Check dashboard regularly

2. Set up billing alerts

## Additional Tips

1. Use Railway CLI for local development
2. Set up automatic backups
3. Configure health checks
4. Use staging environments for testing 