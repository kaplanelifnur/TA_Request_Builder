#!/usr/bin/env python
import certifi
import sys
import os
import json
import re
import socket
import ipaddress
from urllib.parse import urlparse
import requests
from requests.adapters import HTTPAdapter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option
from splunklib.client import connect


class SSRFProtectedAdapter(HTTPAdapter):
    """Custom adapter that validates resolved IPs before connecting."""
    
    def __init__(self, block_private_ips=True, *args, **kwargs):
        self.block_private_ips = block_private_ips
        super().__init__(*args, **kwargs)
    
    def send(self, request, *args, **kwargs):
        parsed = urlparse(request.url)
        hostname = parsed.hostname
        
        if hostname and self.block_private_ips:
            try:
                resolved_ips = socket.getaddrinfo(hostname, None)
                for family, socktype, proto, canonname, sockaddr in resolved_ips:
                    ip = sockaddr[0]
                    ip_obj = ipaddress.ip_address(ip)
                    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local:
                        raise ValueError(f"SSRF Protection: Access to private/internal IP {ip} is blocked")
            except socket.gaierror:
                pass
        
        return super().send(request, *args, **kwargs)


class SecurityConfig:
    """Security configuration loaded from Splunk conf files."""
    
    def __init__(self, service):
        self.allowed_schemes = ["https", "http"]
        self.allowed_domains = []
        self.blocked_domains = []
        self.block_private_ips = True
        self.force_ssl_verify = False
        self.allow_ssl_verify_disable = False
        self.min_timeout = 1
        self.max_timeout = 120
        self.default_timeout = 30
        self.max_redirects = 5
        self.max_response_size = 10485760
        self.allowed_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
        
        self._load_from_conf(service)
    
    def _load_from_conf(self, service):
        """Load security settings from Splunk configuration."""
        try:
            app_name = "TA_Request_Builder"
            conf_name = "ta_request_builder_settings"
            
            confs = service.confs
            if conf_name in confs:
                conf = confs[conf_name]
                
                if "security" in conf:
                    security_stanza = conf["security"]
                    
                    if hasattr(security_stanza, "allowed_schemes"):
                        schemes = security_stanza.allowed_schemes
                        if schemes:
                            self.allowed_schemes = [s.strip().lower() for s in schemes.split(",") if s.strip()]
                    
                    if hasattr(security_stanza, "allowed_domains"):
                        domains = security_stanza.allowed_domains
                        if domains:
                            self.allowed_domains = [d.strip().lower() for d in domains.split(",") if d.strip()]
                    
                    if hasattr(security_stanza, "blocked_domains"):
                        domains = security_stanza.blocked_domains
                        if domains:
                            self.blocked_domains = [d.strip().lower() for d in domains.split(",") if d.strip()]
                    
                    if hasattr(security_stanza, "block_private_ips"):
                        self.block_private_ips = str(security_stanza.block_private_ips).lower() in ["true", "1", "yes"]
                    
                    if hasattr(security_stanza, "force_ssl_verify"):
                        self.force_ssl_verify = str(security_stanza.force_ssl_verify).lower() in ["true", "1", "yes"]
                    
                    if hasattr(security_stanza, "allow_ssl_verify_disable"):
                        self.allow_ssl_verify_disable = str(security_stanza.allow_ssl_verify_disable).lower() in ["true", "1", "yes"]
                
                if "limits" in conf:
                    limits_stanza = conf["limits"]
                    
                    if hasattr(limits_stanza, "min_timeout"):
                        try:
                            self.min_timeout = max(1, int(limits_stanza.min_timeout))
                        except (ValueError, TypeError):
                            pass
                    
                    if hasattr(limits_stanza, "max_timeout"):
                        try:
                            self.max_timeout = min(300, int(limits_stanza.max_timeout))
                        except (ValueError, TypeError):
                            pass
                    
                    if hasattr(limits_stanza, "default_timeout"):
                        try:
                            self.default_timeout = int(limits_stanza.default_timeout)
                        except (ValueError, TypeError):
                            pass
                    
                    if hasattr(limits_stanza, "max_redirects"):
                        try:
                            self.max_redirects = min(10, max(0, int(limits_stanza.max_redirects)))
                        except (ValueError, TypeError):
                            pass
                    
                    if hasattr(limits_stanza, "max_response_size"):
                        try:
                            self.max_response_size = int(limits_stanza.max_response_size)
                        except (ValueError, TypeError):
                            pass
                    
                    if hasattr(limits_stanza, "allowed_methods"):
                        methods = limits_stanza.allowed_methods
                        if methods:
                            self.allowed_methods = [m.strip().upper() for m in methods.split(",") if m.strip()]
        
        except Exception:
            pass
    
    def validate_timeout(self, timeout):
        """Validate and clamp timeout value."""
        try:
            timeout = int(timeout)
        except (ValueError, TypeError):
            timeout = self.default_timeout
        return max(self.min_timeout, min(self.max_timeout, timeout))


def validate_url(url, config):
    """Validate URL against security policies."""
    if not url:
        raise ValueError("URL is required")
    
    if not isinstance(url, str):
        raise ValueError("URL must be a string")
    
    url = url.strip()
    
    if len(url) > 2048:
        raise ValueError("URL exceeds maximum length of 2048 characters")
    
    try:
        parsed = urlparse(url)
    except Exception:
        raise ValueError("Invalid URL format")
    
    scheme = (parsed.scheme or "").lower()
    if scheme not in config.allowed_schemes:
        raise ValueError(f"URL scheme '{scheme}' is not allowed. Allowed: {', '.join(config.allowed_schemes)}")
    
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise ValueError("URL must contain a valid hostname")
    
    dangerous_patterns = [
        r"^localhost$",
        r"^127\.\d+\.\d+\.\d+$",
        r"^0\.0\.0\.0$",
        r"^\[::1\]$",
        r"^\[::\]$",
        r"^169\.254\.\d+\.\d+$",
        r"^metadata\.google\.internal$",
        r"^169\.254\.169\.254$",
    ]
    
    if config.block_private_ips:
        for pattern in dangerous_patterns:
            if re.match(pattern, hostname, re.IGNORECASE):
                raise ValueError(f"Access to '{hostname}' is blocked for security reasons")
    
    if config.blocked_domains:
        for blocked in config.blocked_domains:
            if hostname == blocked or hostname.endswith("." + blocked):
                raise ValueError(f"Domain '{hostname}' is blocked by security policy")
    
    if config.allowed_domains:
        allowed = False
        for domain in config.allowed_domains:
            if hostname == domain or hostname.endswith("." + domain):
                allowed = True
                break
        if not allowed:
            raise ValueError(f"Domain '{hostname}' is not in the allowed domains list")
    
    return url


def validate_method(method, config):
    """Validate HTTP method."""
    method = (method or "GET").upper().strip()
    if method not in config.allowed_methods:
        raise ValueError(f"HTTP method '{method}' is not allowed. Allowed: {', '.join(config.allowed_methods)}")
    return method


def safe_json_parse(data, default=None):
    """Safely parse JSON string."""
    if not data:
        return default if default is not None else {}
    if isinstance(data, dict):
        return data
    if isinstance(data, str):
        try:
            return json.loads(data)
        except json.JSONDecodeError:
            return default if default is not None else {}
    return default if default is not None else {}


@Configuration()
class ReqCommand(StreamingCommand):
    url = Option(require=False)
    identity = Option(require=False)
    realm = Option(require=False)
    auth_type = Option(require=False, default="basic")
    api_key_header = Option(require=False, default="x-api-key")

    def stream(self, records):
        session_key = self.metadata.searchinfo.session_key
        username, password = None, None

        service = connect(token=session_key)
        
        config = SecurityConfig(service)

        if self.identity and self.realm:
            for cred in service.storage_passwords:
                if cred.realm == self.realm and cred.username == self.identity:
                    username = cred.username
                    password = cred.clear_password
                    break

        # Normalize auth_type to lowercase for comparison
        auth_type = (self.auth_type or "basic").lower().strip()

        session = requests.Session()
        adapter = SSRFProtectedAdapter(block_private_ips=config.block_private_ips)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.max_redirects = config.max_redirects

        for record in records:
            try:
                url = record.get("url", self.url)
                url = validate_url(url, config)
                
                method = record.get("method", "GET")
                method = validate_method(method, config)
                
                data = record.get("data")
                hdrs = safe_json_parse(record.get("headers"), {})
                cookies = safe_json_parse(record.get("cookies"), {})
                
                timeout = config.validate_timeout(record.get("timeout", config.default_timeout))
                
                if config.force_ssl_verify:
                    verify_mode = True
                elif config.allow_ssl_verify_disable:
                    verify_input = str(record.get("verify", "true")).lower().strip()
                    verify_mode = verify_input in ["true", "1", "yes", "on"]
                else:
                    verify_mode = True

                if auth_type == "basic" and username and password:
                    auth = (username, password)
                elif auth_type == "bearer" and password:
                    hdrs["Authorization"] = f"Bearer {password}"
                    auth = None
                elif auth_type == "apikey" and password:
                    hdrs[self.api_key_header] = password
                    auth = None
                else:
                    auth = None

                if data and isinstance(data, str):
                    data = data.encode("utf-8")

                resp = session.request(
                    method,
                    url,
                    headers=hdrs,
                    cookies=cookies,
                    data=data,
                    auth=auth,
                    timeout=timeout,
                    verify=certifi.where() if verify_mode else False,
                    allow_redirects=config.max_redirects > 0,
                    stream=True
                )

                content_length = resp.headers.get("Content-Length")
                if content_length and int(content_length) > config.max_response_size:
                    raise ValueError(f"Response size exceeds maximum allowed size of {config.max_response_size} bytes")
                
                response_content = ""
                bytes_read = 0
                for chunk in resp.iter_content(chunk_size=8192, decode_unicode=True):
                    if chunk:
                        if isinstance(chunk, bytes):
                            chunk = chunk.decode("utf-8", errors="replace")
                        bytes_read += len(chunk.encode("utf-8"))
                        if bytes_read > config.max_response_size:
                            response_content += chunk[:config.max_response_size - bytes_read + len(chunk.encode("utf-8"))]
                            response_content += "\n[TRUNCATED: Response exceeded maximum size]"
                            break
                        response_content += chunk

                record["status_code"] = resp.status_code
                record["response"] = response_content
                record["response_headers"] = json.dumps(dict(resp.headers))
                record["ssl_verify"] = verify_mode

            except ValueError as e:
                record["error"] = f"Validation Error: {str(e)}"
            except requests.exceptions.SSLError as e:
                record["error"] = f"SSL Error: {str(e)}"
            except requests.exceptions.Timeout:
                record["error"] = f"Request timed out after {timeout} seconds"
            except requests.exceptions.TooManyRedirects:
                record["error"] = f"Too many redirects (max: {config.max_redirects})"
            except requests.exceptions.ConnectionError as e:
                record["error"] = f"Connection Error: {str(e)}"
            except requests.exceptions.RequestException as e:
                record["error"] = f"Request Error: {str(e)}"
            except Exception as e:
                record["error"] = f"Error: {str(e)}"

            yield record
        
        session.close()


if __name__ == "__main__":
    dispatch(ReqCommand, sys.argv, sys.stdin, sys.stdout, __name__)
