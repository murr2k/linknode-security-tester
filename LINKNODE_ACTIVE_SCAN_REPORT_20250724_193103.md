# Linknode.com Active Security Scan Report

**Date:** 2025-07-24 19:31:03
**Scan Type:** Active Security Scan with OWASP Top 10 Testing

## OWASP Top 10 Compliance


## Detailed Findings

### High Risk (1 issues)

#### Cloud Metadata Potentially Exposed
- **URL:** https://linknode.com/opc/v1/instance/
- **Description:** The Cloud Metadata Attack attempts to abuse a misconfigured NGINX server in order to access the instance metadata maintained by cloud service providers such as AWS, GCP and Azure.
All of these providers provide metadata via an internal unroutable IP address '169.254.169.254' - this can be exposed by incorrectly configured NGINX servers and accessed by using this IP address in the Host header field.
- **Solution:** Do not trust any user data in NGINX configs. In this case it is probably the use of the $host variable which is set from the 'Host' header and can be controlled by an attacker.

### Medium Risk (23 issues)

#### CSP: Failure to Define Directive with No Fallback
- **URL:** https://linknode.com/private/
- **Description:** The Content Security Policy fails to define one of the directives that has no fallback. Missing/excluding them is the same as allowing anything.
- **Solution:** Ensure that your web server, application server, load balancer, etc. is properly configured to set the Content-Security-Policy header.

#### Content Security Policy (CSP) Header Not Set
- **URL:** https://linknode.com/api/
- **Description:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.
- **Solution:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

#### CSP: Failure to Define Directive with No Fallback
- **URL:** https://linknode.com/admin/
- **Description:** The Content Security Policy fails to define one of the directives that has no fallback. Missing/excluding them is the same as allowing anything.
- **Solution:** Ensure that your web server, application server, load balancer, etc. is properly configured to set the Content-Security-Policy header.

#### CSP: Wildcard Directive
- **URL:** https://linknode.com/private/
- **Description:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks. Including (but not limited to) Cross Site Scripting (XSS), and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.
- **Solution:** Ensure that your web server, application server, load balancer, etc. is properly configured to set the Content-Security-Policy header.

#### CSP: Wildcard Directive
- **URL:** https://linknode.com/admin/
- **Description:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks. Including (but not limited to) Cross Site Scripting (XSS), and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.
- **Solution:** Ensure that your web server, application server, load balancer, etc. is properly configured to set the Content-Security-Policy header.

#### CSP: script-src unsafe-inline
- **URL:** https://linknode.com/private/
- **Description:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks. Including (but not limited to) Cross Site Scripting (XSS), and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.
- **Solution:** Ensure that your web server, application server, load balancer, etc. is properly configured to set the Content-Security-Policy header.

#### CSP: script-src unsafe-inline
- **URL:** https://linknode.com/admin/
- **Description:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks. Including (but not limited to) Cross Site Scripting (XSS), and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.
- **Solution:** Ensure that your web server, application server, load balancer, etc. is properly configured to set the Content-Security-Policy header.

#### CSP: style-src unsafe-inline
- **URL:** https://linknode.com/private/
- **Description:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks. Including (but not limited to) Cross Site Scripting (XSS), and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.
- **Solution:** Ensure that your web server, application server, load balancer, etc. is properly configured to set the Content-Security-Policy header.

#### CSP: style-src unsafe-inline
- **URL:** https://linknode.com/admin/
- **Description:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks. Including (but not limited to) Cross Site Scripting (XSS), and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.
- **Solution:** Ensure that your web server, application server, load balancer, etc. is properly configured to set the Content-Security-Policy header.

#### CSP: Failure to Define Directive with No Fallback
- **URL:** https://linknode.com/*.json$
- **Description:** The Content Security Policy fails to define one of the directives that has no fallback. Missing/excluding them is the same as allowing anything.
- **Solution:** Ensure that your web server, application server, load balancer, etc. is properly configured to set the Content-Security-Policy header.

### Low Risk (29 issues)

#### Server Leaks Version Information via "Server" HTTP Response Header Field
- **URL:** https://linknode.com/robots.txt
- **Description:** The web/application server is leaking version information via the "Server" HTTP response header. Access to such information may facilitate attackers identifying other vulnerabilities your web/application server is subject to.
- **Solution:** Ensure that your web server, application server, load balancer, etc. is configured to suppress the "Server" header or provide generic details.

#### Server Leaks Version Information via "Server" HTTP Response Header Field
- **URL:** https://linknode.com/private/
- **Description:** The web/application server is leaking version information via the "Server" HTTP response header. Access to such information may facilitate attackers identifying other vulnerabilities your web/application server is subject to.
- **Solution:** Ensure that your web server, application server, load balancer, etc. is configured to suppress the "Server" header or provide generic details.

#### Server Leaks Version Information via "Server" HTTP Response Header Field
- **URL:** https://linknode.com/sitemap.xml
- **Description:** The web/application server is leaking version information via the "Server" HTTP response header. Access to such information may facilitate attackers identifying other vulnerabilities your web/application server is subject to.
- **Solution:** Ensure that your web server, application server, load balancer, etc. is configured to suppress the "Server" header or provide generic details.

#### Server Leaks Version Information via "Server" HTTP Response Header Field
- **URL:** https://linknode.com/api/
- **Description:** The web/application server is leaking version information via the "Server" HTTP response header. Access to such information may facilitate attackers identifying other vulnerabilities your web/application server is subject to.
- **Solution:** Ensure that your web server, application server, load balancer, etc. is configured to suppress the "Server" header or provide generic details.

#### Server Leaks Version Information via "Server" HTTP Response Header Field
- **URL:** https://linknode.com/admin/
- **Description:** The web/application server is leaking version information via the "Server" HTTP response header. Access to such information may facilitate attackers identifying other vulnerabilities your web/application server is subject to.
- **Solution:** Ensure that your web server, application server, load balancer, etc. is configured to suppress the "Server" header or provide generic details.

#### Strict-Transport-Security Header Not Set
- **URL:** https://linknode.com/api/
- **Description:** HTTP Strict Transport Security (HSTS) is a web security policy mechanism whereby a web server declares that complying user agents (such as a web browser) are to interact with it using only secure HTTPS connections (i.e. HTTP layered over TLS/SSL). HSTS is an IETF standards track protocol and is specified in RFC 6797.
- **Solution:** Ensure that your web server, application server, load balancer, etc. is configured to enforce Strict-Transport-Security.

#### Server Leaks Version Information via "Server" HTTP Response Header Field
- **URL:** https://linknode.com
- **Description:** The web/application server is leaking version information via the "Server" HTTP response header. Access to such information may facilitate attackers identifying other vulnerabilities your web/application server is subject to.
- **Solution:** Ensure that your web server, application server, load balancer, etc. is configured to suppress the "Server" header or provide generic details.

#### Server Leaks Version Information via "Server" HTTP Response Header Field
- **URL:** https://linknode.com/
- **Description:** The web/application server is leaking version information via the "Server" HTTP response header. Access to such information may facilitate attackers identifying other vulnerabilities your web/application server is subject to.
- **Solution:** Ensure that your web server, application server, load balancer, etc. is configured to suppress the "Server" header or provide generic details.

#### Server Leaks Version Information via "Server" HTTP Response Header Field
- **URL:** https://linknode.com/*.json$
- **Description:** The web/application server is leaking version information via the "Server" HTTP response header. Access to such information may facilitate attackers identifying other vulnerabilities your web/application server is subject to.
- **Solution:** Ensure that your web server, application server, load balancer, etc. is configured to suppress the "Server" header or provide generic details.

#### Server Leaks Version Information via "Server" HTTP Response Header Field
- **URL:** https://linknode.com/favicon.ico
- **Description:** The web/application server is leaking version information via the "Server" HTTP response header. Access to such information may facilitate attackers identifying other vulnerabilities your web/application server is subject to.
- **Solution:** Ensure that your web server, application server, load balancer, etc. is configured to suppress the "Server" header or provide generic details.

### Informational Risk (55 issues)

#### Re-examine Cache-control Directives
- **URL:** https://linknode.com/sitemap.xml
- **Description:** The cache-control header has not been set properly or is missing, allowing the browser and proxies to cache content. For static assets like css, js, or image files this might be intended, however, the resources should be reviewed to ensure that no sensitive content will be cached.
- **Solution:** For secure content, ensure the cache-control HTTP header is set with "no-cache, no-store, must-revalidate". If an asset should be cached consider setting the directives "public, max-age, immutable".

#### Re-examine Cache-control Directives
- **URL:** https://linknode.com/robots.txt
- **Description:** The cache-control header has not been set properly or is missing, allowing the browser and proxies to cache content. For static assets like css, js, or image files this might be intended, however, the resources should be reviewed to ensure that no sensitive content will be cached.
- **Solution:** For secure content, ensure the cache-control HTTP header is set with "no-cache, no-store, must-revalidate". If an asset should be cached consider setting the directives "public, max-age, immutable".

#### Re-examine Cache-control Directives
- **URL:** https://linknode.com/*.json$
- **Description:** The cache-control header has not been set properly or is missing, allowing the browser and proxies to cache content. For static assets like css, js, or image files this might be intended, however, the resources should be reviewed to ensure that no sensitive content will be cached.
- **Solution:** For secure content, ensure the cache-control HTTP header is set with "no-cache, no-store, must-revalidate". If an asset should be cached consider setting the directives "public, max-age, immutable".

#### Re-examine Cache-control Directives
- **URL:** https://linknode.com/
- **Description:** The cache-control header has not been set properly or is missing, allowing the browser and proxies to cache content. For static assets like css, js, or image files this might be intended, however, the resources should be reviewed to ensure that no sensitive content will be cached.
- **Solution:** For secure content, ensure the cache-control HTTP header is set with "no-cache, no-store, must-revalidate". If an asset should be cached consider setting the directives "public, max-age, immutable".

#### Re-examine Cache-control Directives
- **URL:** https://linknode.com
- **Description:** The cache-control header has not been set properly or is missing, allowing the browser and proxies to cache content. For static assets like css, js, or image files this might be intended, however, the resources should be reviewed to ensure that no sensitive content will be cached.
- **Solution:** For secure content, ensure the cache-control HTTP header is set with "no-cache, no-store, must-revalidate". If an asset should be cached consider setting the directives "public, max-age, immutable".

#### Information Disclosure - Suspicious Comments
- **URL:** https://linknode.com
- **Description:** The response appears to contain suspicious comments which may help an attacker.
- **Solution:** Remove all comments that return information that may help an attacker and fix any underlying problems they refer to.

#### Information Disclosure - Suspicious Comments
- **URL:** https://linknode.com/
- **Description:** The response appears to contain suspicious comments which may help an attacker.
- **Solution:** Remove all comments that return information that may help an attacker and fix any underlying problems they refer to.

#### Information Disclosure - Suspicious Comments
- **URL:** https://linknode.com/*.json$
- **Description:** The response appears to contain suspicious comments which may help an attacker.
- **Solution:** Remove all comments that return information that may help an attacker and fix any underlying problems they refer to.

#### User Agent Fuzzer
- **URL:** https://linknode.com/favicon.ico
- **Description:** Check for differences in response based on fuzzed User Agent (eg. mobile sites, access as a Search Engine Crawler). Compares the response statuscode and the hashcode of the response body with the original response.
- **Solution:** 

#### User Agent Fuzzer
- **URL:** https://linknode.com/admin
- **Description:** Check for differences in response based on fuzzed User Agent (eg. mobile sites, access as a Search Engine Crawler). Compares the response statuscode and the hashcode of the response body with the original response.
- **Solution:** 

## Recommendations

1. **Immediate Actions (24 hours):**
   - Address all Critical and High risk vulnerabilities
   - Implement security headers (CSP, X-Frame-Options, etc.)

2. **Short-term (1 week):**
   - Fix CORS misconfigurations
   - Secure administrative endpoints
   - Implement input validation

3. **Long-term:**
   - Establish regular security testing schedule
   - Implement security monitoring
   - Security awareness training
