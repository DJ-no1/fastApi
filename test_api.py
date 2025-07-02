#!/usr/bin/env python3
"""
Simple test script for URL Intelligence API
"""

import requests
import json

API_BASE = "http://localhost:8001"

def test_url(url):
    """Test a single URL"""
    print(f"\n🔍 Testing: {url}")
    print("-" * 50)
    
    try:
        response = requests.post(
            f"{API_BASE}/analyze", 
            json={"url": url},
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Analysis completed in {data['analysis_time']}")
            print(f"🔒 Security Score: {data['security']['safety_score']}/100")
            print(f"⚡ Load Speed: {data['performance']['load_speed']}")
            print(f"🚨 Suspicious Patterns: {data['security']['suspicious_patterns']}")
            print(f"🌐 Domain: {data['domain']['domain']}")
        else:
            print(f"❌ Error: {response.status_code} - {response.text}")
            
    except Exception as e:
        print(f"❌ Request failed: {e}")

def main():
    # Test various types of websites
    test_urls = [
        "https://github.com",                    # Good site
        "http://neverssl.com",                   # No SSL
        "https://expired.badssl.com",            # SSL issues
        "http://93.184.216.34",                  # IP address
        "https://google.com",                    # Popular site
        "http://example.com",                    # Test site
    ]
    
    print("🚀 URL Intelligence API Tester")
    print("=" * 50)
    
    for url in test_urls:
        test_url(url)
    
    print("\n✨ All tests completed!")

if __name__ == "__main__":
    main()
