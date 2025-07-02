from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, HttpUrl
import httpx
import time
from bs4 import BeautifulSoup
import whois
from urllib.parse import urlparse
import re
import ssl
import socket
from typing import Optional, List, Dict, Any
import asyncio
from datetime import datetime

app = FastAPI(
    title="URL Intelligence API",
    description="Simple URL analysis and intelligence tool",
    version="1.0.0"
)

# Pydantic Models
class URLRequest(BaseModel):
    url: HttpUrl

class SecurityInfo(BaseModel):
    ssl_enabled: bool
    ssl_valid: bool
    https_redirect: bool
    suspicious_patterns: List[str]
    safety_score: int

class PerformanceInfo(BaseModel):
    response_time: float
    page_size: int
    status_code: int
    load_speed: str

class ContentInfo(BaseModel):
    title: Optional[str]
    description: Optional[str]
    meta_keywords: Optional[str]
    word_count: int
    has_forms: bool
    external_links: int

class TechInfo(BaseModel):
    server: Optional[str]
    technologies: List[str]
    cms_detected: Optional[str]
    frameworks: List[str]

class DomainInfo(BaseModel):
    domain: str
    registrar: Optional[str]
    creation_date: Optional[str]
    expiration_date: Optional[str]
    country: Optional[str]

class URLAnalysisResponse(BaseModel):
    url: str
    analysis_time: str
    security: SecurityInfo
    performance: PerformanceInfo
    content: ContentInfo
    technology: TechInfo
    domain: DomainInfo

class URLAnalyzer:
    def __init__(self):
        self.timeout = 15
        
    async def analyze_url(self, url: str) -> URLAnalysisResponse:
        """Main analysis function"""
        start_time = time.time()
        
        print(f"Starting analysis for: {url}")
        
        # Try to fetch content, but continue with partial analysis if blocked
        response = None
        soup = None
        fetch_error = None
        
        try:
            # Fetch URL content with better headers to avoid blocking
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            }
            
            async with httpx.AsyncClient(
                timeout=self.timeout, 
                follow_redirects=True,
                headers=headers
            ) as client:
                response = await client.get(url)
                print(f"Successfully fetched {url} - Status: {response.status_code}")
                soup = BeautifulSoup(response.text, 'html.parser')
                
        except Exception as e:
            print(f"Content fetch failed for {url}: {str(e)} - Continuing with partial analysis")
            fetch_error = str(e)
        
        try:
            # Run all analyses (some will work even without content)
            print("Running security analysis...")
            security_info = await self._analyze_security(url, response)
            
            print("Running performance analysis...")
            performance_info = self._analyze_performance(response, start_time, fetch_error)
            
            print("Running content analysis...")
            content_info = self._analyze_content(soup)
            
            print("Running technology analysis...")
            tech_info = self._analyze_technology(response, soup)
            
            print("Running domain analysis...")
            domain_info = await self._analyze_domain(url)
            
            analysis_time = f"{time.time() - start_time:.2f}s"
            
            print(f"Analysis completed in {analysis_time}")
            
            return URLAnalysisResponse(
                url=url,
                analysis_time=analysis_time,
                security=security_info,
                performance=performance_info,
                content=content_info,
                technology=tech_info,
                domain=domain_info
            )
            
        except Exception as e:
            print(f"Analysis error for {url}: {str(e)}")
            print(f"Error type: {type(e).__name__}")
            import traceback
            traceback.print_exc()
            raise HTTPException(status_code=400, detail=f"Analysis failed: {str(e)}")
    
    async def _analyze_security(self, url: str, response) -> SecurityInfo:
        """Security analysis"""
        parsed_url = urlparse(url)
        ssl_enabled = parsed_url.scheme == 'https'
        
        # Check SSL certificate validity
        ssl_valid = False
        if ssl_enabled:
            ssl_valid = await self._check_ssl_certificate(parsed_url.hostname)
        
        # Check for HTTPS redirect (only if HTTP)
        https_redirect = False
        if not ssl_enabled:
            try:
                https_url = url.replace('http://', 'https://')
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
                async with httpx.AsyncClient(timeout=5, headers=headers) as client:
                    https_response = await client.get(https_url)
                    https_redirect = https_response.status_code == 200
            except Exception as e:
                print(f"HTTPS redirect check failed: {e}")
                pass
        
        # Detect suspicious patterns in URL itself
        suspicious_patterns = self._detect_suspicious_patterns(url, response.text if response else "")
        
        # Add pattern if content couldn't be fetched (might be blocked)
        if response is None:
            suspicious_patterns.append("Content blocked or unreachable")
        
        # Calculate safety score
        safety_score = self._calculate_safety_score(ssl_enabled, ssl_valid, suspicious_patterns)
        
        return SecurityInfo(
            ssl_enabled=ssl_enabled,
            ssl_valid=ssl_valid,
            https_redirect=https_redirect,
            suspicious_patterns=suspicious_patterns,
            safety_score=safety_score
        )
    
    async def _check_ssl_certificate(self, hostname: str) -> bool:
        """Check SSL certificate validity"""
        try:
            if not hostname:
                return False
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    return cert is not None
        except Exception as e:
            print(f"SSL check failed for {hostname}: {e}")
            return False
    
    def _detect_suspicious_patterns(self, url: str, content: str) -> List[str]:
        """Detect suspicious patterns"""
        patterns = []
        
        # URL-based checks
        if re.search(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', url):
            patterns.append("IP address in URL")
        
        if len(urlparse(url).hostname) > 50:
            patterns.append("Unusually long domain name")
        
        # Content-based checks
        suspicious_keywords = ['verify account', 'update payment', 'suspended account', 'click here now']
        for keyword in suspicious_keywords:
            if keyword.lower() in content.lower():
                patterns.append(f"Suspicious keyword: {keyword}")
        
        if content.count('<script>') > 10:
            patterns.append("Excessive JavaScript")
        
        return patterns
    
    def _calculate_safety_score(self, ssl_enabled: bool, ssl_valid: bool, suspicious_patterns: List[str]) -> int:
        """Calculate safety score (0-100)"""
        score = 100
        
        if not ssl_enabled:
            score -= 25
        elif not ssl_valid:
            score -= 15
        
        score -= len(suspicious_patterns) * 10
        
        return max(0, min(100, score))
    
    def _analyze_performance(self, response, start_time: float, fetch_error: str = None) -> PerformanceInfo:
        """Performance analysis"""
        response_time = time.time() - start_time
        
        if response is None:
            # If content couldn't be fetched, return limited performance info
            return PerformanceInfo(
                response_time=round(response_time, 3),
                page_size=0,
                status_code=0,
                load_speed="Blocked/Unreachable"
            )
        
        page_size = len(response.content)
        
        # Determine load speed category
        if response_time < 1:
            load_speed = "Fast"
        elif response_time < 3:
            load_speed = "Medium"
        else:
            load_speed = "Slow"
        
        return PerformanceInfo(
            response_time=round(response_time, 3),
            page_size=page_size,
            status_code=response.status_code,
            load_speed=load_speed
        )
    
    def _analyze_content(self, soup: BeautifulSoup) -> ContentInfo:
        """Content analysis"""
        if soup is None:
            # If content couldn't be fetched, return default values
            return ContentInfo(
                title="Unable to fetch - Content blocked/restricted",
                description="Content could not be analyzed due to access restrictions",
                meta_keywords=None,
                word_count=0,
                has_forms=False,
                external_links=0
            )
        
        # Extract title
        title_tag = soup.find('title')
        title = title_tag.text.strip() if title_tag else None
        
        # Extract description
        desc_tag = soup.find('meta', attrs={'name': 'description'})
        description = desc_tag.get('content') if desc_tag else None
        
        # Extract keywords
        keywords_tag = soup.find('meta', attrs={'name': 'keywords'})
        keywords = keywords_tag.get('content') if keywords_tag else None
        
        # Count words
        text_content = soup.get_text()
        word_count = len(text_content.split())
        
        # Check for forms
        has_forms = len(soup.find_all('form')) > 0
        
        # Count external links
        external_links = 0
        for link in soup.find_all('a', href=True):
            href = link['href']
            if href.startswith('http') and not href.startswith(('#', '/', 'mailto:')):
                external_links += 1
        
        return ContentInfo(
            title=title,
            description=description,
            meta_keywords=keywords,
            word_count=word_count,
            has_forms=has_forms,
            external_links=external_links
        )
    
    def _analyze_technology(self, response, soup: BeautifulSoup) -> TechInfo:
        """Technology stack analysis"""
        if response is None:
            # If content couldn't be fetched, return minimal info
            return TechInfo(
                server="Unable to fetch - Content blocked",
                technologies=[],
                cms_detected=None,
                frameworks=[]
            )
        
        headers = dict(response.headers)
        
        # Server detection
        server = headers.get('server', 'Unknown')
        
        # Technology detection
        technologies = []
        frameworks = []
        cms_detected = None
        
        # Check headers for technologies
        if 'x-powered-by' in headers:
            technologies.append(headers['x-powered-by'])
        
        if soup is not None:
            # Check HTML content for frameworks/libraries
            html_content = str(soup)
            
            if 'react' in html_content.lower():
                frameworks.append('React')
            if 'vue' in html_content.lower():
                frameworks.append('Vue.js')
            if 'angular' in html_content.lower():
                frameworks.append('Angular')
            if 'jquery' in html_content.lower():
                technologies.append('jQuery')
            if 'bootstrap' in html_content.lower():
                technologies.append('Bootstrap')
            
            # CMS detection
            if 'wp-content' in html_content or 'wordpress' in html_content.lower():
                cms_detected = 'WordPress'
            elif 'drupal' in html_content.lower():
                cms_detected = 'Drupal'
            elif 'joomla' in html_content.lower():
                cms_detected = 'Joomla'
        
        return TechInfo(
            server=server,
            technologies=technologies,
            cms_detected=cms_detected,
            frameworks=frameworks
        )
    
    async def _analyze_domain(self, url: str) -> DomainInfo:
        """Domain information analysis"""
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            if not domain:
                return DomainInfo(
                    domain="Unknown",
                    registrar="Unable to fetch",
                    creation_date="Unable to fetch", 
                    expiration_date="Unable to fetch",
                    country="Unable to fetch"
                )
            
            print(f"Fetching WHOIS for domain: {domain}")
            
            try:
                # WHOIS lookup with timeout
                domain_info = whois.whois(domain)
                
                # Extract information safely
                registrar = None
                creation_date = None
                expiration_date = None
                country = None
                
                if hasattr(domain_info, 'registrar') and domain_info.registrar:
                    registrar = str(domain_info.registrar)
                
                if hasattr(domain_info, 'creation_date') and domain_info.creation_date:
                    if isinstance(domain_info.creation_date, list):
                        creation_date = str(domain_info.creation_date[0])
                    else:
                        creation_date = str(domain_info.creation_date)
                
                if hasattr(domain_info, 'expiration_date') and domain_info.expiration_date:
                    if isinstance(domain_info.expiration_date, list):
                        expiration_date = str(domain_info.expiration_date[0])
                    else:
                        expiration_date = str(domain_info.expiration_date)
                
                if hasattr(domain_info, 'country') and domain_info.country:
                    country = str(domain_info.country)
                
            except Exception as whois_error:
                print(f"WHOIS lookup failed for {domain}: {whois_error}")
                registrar = "Unable to fetch"
                creation_date = "Unable to fetch"
                expiration_date = "Unable to fetch"
                country = "Unable to fetch"
            
            return DomainInfo(
                domain=domain,
                registrar=registrar or "Unable to fetch",
                creation_date=creation_date or "Unable to fetch",
                expiration_date=expiration_date or "Unable to fetch",
                country=country or "Unable to fetch"
            )
        
        except Exception as e:
            print(f"Domain analysis failed: {e}")
            return DomainInfo(
                domain="Unknown",
                registrar="Unable to fetch",
                creation_date="Unable to fetch",
                expiration_date="Unable to fetch", 
                country="Unable to fetch"
            )

# Initialize analyzer
analyzer = URLAnalyzer()

@app.get("/")
async def root():
    return {
        "message": "URL Intelligence API",
        "version": "1.0.0",
        "docs": "/docs",
        "example": "POST /analyze with {'url': 'https://example.com'}",
        "browser_examples": {
            "analyze_github": "/analyze-get?url=https://github.com",
            "analyze_http_site": "/analyze-get?url=http://neverssl.com",
            "test_connectivity": "/test-get?url=https://google.com"
        }
    }

@app.get("/analyze-get")
async def analyze_url_get(url: str):
    """Analyze a URL via GET request for browser testing"""
    try:
        # Validate URL format
        if not url.startswith(('http://', 'https://')):
            return {"error": "URL must start with http:// or https://"}
        
        # Use the same analyzer as POST endpoint
        result = await analyzer.analyze_url(url)
        return result
    except Exception as e:
        return {"error": f"Analysis failed: {str(e)}"}

@app.get("/test-get")
async def test_connectivity_get(url: str):
    """Test connectivity via GET request for browser testing"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    try:
        async with httpx.AsyncClient(timeout=10, headers=headers) as client:
            response = await client.head(url)
            return {
                "url": url,
                "reachable": True,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "message": "URL is accessible"
            }
    except httpx.TimeoutException:
        return {
            "url": url,
            "reachable": False,
            "error": "timeout",
            "message": "Request timed out - server may be slow or blocking requests"
        }
    except httpx.ConnectError:
        return {
            "url": url,
            "reachable": False,
            "error": "connection_failed",
            "message": "Connection failed - URL may be blocked by ISP/firewall or server is down"
        }
    except Exception as e:
        return {
            "url": url,
            "reachable": False,
            "error": "unknown",
            "message": f"Error: {str(e)}"
        }

@app.post("/analyze", response_model=URLAnalysisResponse)
async def analyze_url(request: URLRequest):
    """Analyze a URL and return intelligence report"""
    url = str(request.url)
    result = await analyzer.analyze_url(url)
    return result

@app.post("/test-connectivity")
async def test_connectivity(request: URLRequest):
    """Test if a URL is reachable without full analysis"""
    url = str(request.url)
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    try:
        async with httpx.AsyncClient(timeout=10, headers=headers) as client:
            response = await client.head(url)  # HEAD request instead of GET
            return {
                "url": url,
                "reachable": True,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "message": "URL is accessible"
            }
    except httpx.TimeoutException:
        return {
            "url": url,
            "reachable": False,
            "error": "timeout",
            "message": "Request timed out - server may be slow or blocking requests"
        }
    except httpx.ConnectError:
        return {
            "url": url,
            "reachable": False,
            "error": "connection_failed",
            "message": "Connection failed - URL may be blocked by ISP/firewall or server is down"
        }
    except Exception as e:
        return {
            "url": url,
            "reachable": False,
            "error": "unknown",
            "message": f"Error: {str(e)}"
        }

# Health check endpoint for Docker
@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring and Docker health checks"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "FastAPI URL Intelligence Service"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
