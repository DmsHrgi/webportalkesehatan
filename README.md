# Healthcare Portal

A comprehensive healthcare management platform built with Flask and deployed on Vercel.

## Features

- User authentication and registration
- Appointment scheduling
- Document upload and management
- Prescription refill requests
- Provider messaging
- Health dashboard with real-time data
- Modern responsive design

## Tech Stack

- **Backend**: Flask, SQLAlchemy, Flask-Login
- **Frontend**: HTML5, Tailwind CSS, JavaScript
- **Database**: SQLite
- **Deployment**: Vercel

## Quick Start

### Local Development

1. Clone the repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the application:
   ```bash
   python app.py
   ```
4. Open http://localhost:5001

## Deployment on Vercel

### Method 1: GitHub Integration (Recommended)

1. Push your code to GitHub
2. Connect your GitHub account to Vercel
3. Import the repository
4. Vercel will automatically deploy your app

### Method 2: Vercel CLI

1. Install Vercel CLI:
   ```bash
   npm install -g vercel
   ```

2. Deploy:
   ```bash
   vercel
   ```

### Method 3: Direct Upload

1. Go to [vercel.com](https://vercel.com)
2. Click "New Project"
3. Upload your project files
4. Configure environment variables

## Environment Variables

In Vercel dashboard, set these environment variables:

- `SECRET_KEY`: Generate with `python -c 'import secrets; print(secrets.token_hex(32))'`
- `DATABASE_URL`: SQLite connection string (optional, will use local SQLite if not set)

## Project Structure

```
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── vercel.json           # Vercel configuration
├── api/index.py          # Vercel serverless handler
├── .gitignore           # Git ignore file
├── templates/           # HTML templates
│   ├── base.html
│   ├── index.html
│   ├── dashboard.html
│   └── ...
├── uploads/             # File upload directory
└── healthcare_portal_schema.sql  # Database schema
```

## License

MIT License
