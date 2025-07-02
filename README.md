# URL Intelligence API

A simple FastAPI-based URL analysis tool that provides security, performance, content, and technology insights for any given URL.

## Features

🔒 **Security Analysis**

- SSL certificate validation
- HTTPS availability check
- Suspicious pattern detection
- Safety scoring (0-100)

⚡ **Performance Metrics**

- Response time measurement
- Page size analysis
- Load speed categorization
- HTTP status code checking

📄 **Content Analysis**

- Title and meta description extraction
- Word count and content structure
- Form detection
- External link counting

🛠️ **Technology Detection**

- Server identification
- Framework detection (React, Vue, Angular)
- CMS identification (WordPress, Drupal, Joomla)
- Library detection (jQuery, Bootstrap)

🌐 **Domain Intelligence**

- WHOIS information
- Registration and expiration dates
- Registrar information
- Country information

## Quick Start

### Option 1: Run with Python

```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python main.py
```

### Option 2: Run with Docker

```bash
# Build and run with Docker Compose
docker-compose up --build
```

### Option 3: Run with uvicorn

```bash
# Install dependencies
pip install -r requirements.txt

# Run with uvicorn
uvicorn main:app --reload
```

## Usage

1. **Start the API** (it will run on http://localhost:8000)

2. **Visit the docs** at http://localhost:8000/docs

3. **Analyze a URL** by making a POST request:

```bash
curl -X POST "http://localhost:8000/analyze" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://github.com"}'
```

### Example Response

```json
{
  "url": "https://github.com",
  "analysis_time": "2.34s",
  "security": {
    "ssl_enabled": true,
    "ssl_valid": true,
    "https_redirect": false,
    "suspicious_patterns": [],
    "safety_score": 100
  },
  "performance": {
    "response_time": 1.234,
    "page_size": 245678,
    "status_code": 200,
    "load_speed": "Medium"
  },
  "content": {
    "title": "GitHub: Let's build from here",
    "description": "GitHub is where over 100 million developers...",
    "meta_keywords": null,
    "word_count": 1542,
    "has_forms": true,
    "external_links": 23
  },
  "technology": {
    "server": "GitHub.com",
    "technologies": ["Ruby on Rails"],
    "cms_detected": null,
    "frameworks": ["React"]
  },
  "domain": {
    "domain": "github.com",
    "registrar": "MarkMonitor, Inc.",
    "creation_date": "2007-10-09",
    "expiration_date": "2024-10-09",
    "country": "US"
  }
}
```

## API Endpoints

- `GET /` - API information
- `POST /analyze` - Analyze a URL
- `GET /health` - Health check
- `GET /docs` - Interactive API documentation

## Requirements

- Python 3.11+
- FastAPI
- httpx
- BeautifulSoup4
- python-whois

## Development

```bash
# Install in development mode
pip install -r requirements.txt

# Run with auto-reload
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

## Deployment

The application is ready for deployment on:

- AWS (EC2, ECS, Lambda)
- Google Cloud Platform
- Heroku
- DigitalOcean
- Any Docker-compatible platform

## Limitations

- This is a simplified version without authentication
- WHOIS lookups may be rate-limited
- Some websites may block automated requests
- SSL certificate validation is basic

## Contributing

Feel free to submit issues and enhancement requests!

## License

MIT License
