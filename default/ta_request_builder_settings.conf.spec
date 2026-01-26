# TA Request Builder Settings Specification
# This file defines the configuration options available for the TA Request Builder app

[security]
allowed_schemes = <string>
* Comma-separated list of allowed URL schemes
* Default: https,http
* For maximum security, set to "https" only

allowed_domains = <string>
* Comma-separated list of allowed domains (whitelist)
* If empty, all domains are allowed (subject to blocked_domains)
* Example: api.example.com,api.trusted.org
* Supports subdomain matching: "example.com" allows "api.example.com"

blocked_domains = <string>
* Comma-separated list of blocked domains (blacklist)
* Requests to these domains will be rejected
* Example: internal.corp,admin.local
* Supports subdomain matching: "corp" blocks "internal.corp"

block_private_ips = <bool>
* Block requests to private/internal IP addresses
* Provides SSRF (Server-Side Request Forgery) protection
* Blocks: localhost, 127.x.x.x, 10.x.x.x, 172.16-31.x.x, 192.168.x.x, 169.254.x.x, etc.
* Also blocks cloud metadata endpoints (169.254.169.254, metadata.google.internal)
* Default: true
* SECURITY: Strongly recommended to keep enabled

force_ssl_verify = <bool>
* Force SSL certificate verification for all requests
* When true, SSL verification cannot be disabled by users
* Default: false

allow_ssl_verify_disable = <bool>
* Allow users to disable SSL verification per-request via the "verify" field
* Only effective when force_ssl_verify is false
* Default: false
* SECURITY: Keep disabled unless absolutely necessary

[limits]
min_timeout = <integer>
* Minimum allowed timeout in seconds
* Default: 1
* Minimum: 1

max_timeout = <integer>
* Maximum allowed timeout in seconds
* Default: 120
* Maximum: 300

default_timeout = <integer>
* Default timeout when not specified in request
* Default: 30

max_redirects = <integer>
* Maximum number of HTTP redirects to follow
* Set to 0 to disable following redirects
* Default: 5
* Maximum: 10

max_response_size = <integer>
* Maximum response body size in bytes
* Responses larger than this will be truncated
* Default: 10485760 (10MB)

allowed_methods = <string>
* Comma-separated list of allowed HTTP methods
* Default: GET,POST,PUT,DELETE,PATCH,HEAD,OPTIONS
