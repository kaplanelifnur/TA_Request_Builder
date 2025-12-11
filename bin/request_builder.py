#!/usr/bin/env python
import certifi
import sys
import os
import json
import requests
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option
from splunklib.client import connect


@Configuration()
class ReqCommand(StreamingCommand):
    url = Option(require=False)
    identity = Option(require=False)
    realm = Option(require=False)

    def stream(self, records):
        session_key = self.metadata.searchinfo.session_key
        username, password = None, None
        auth_type, api_key_header = None, None

        # Fetch credentials from Splunk storage
        if self.identity and self.realm:
            service = connect(token=session_key)
            for cred in service.storage_passwords:
                if cred.realm == self.realm and cred.username == self.identity:
                    username = cred.username
                    password = cred.clear_password
                    break

        # Determine auth type
        if username and username.startswith("bearer_"):
            auth_type = "bearer"
        elif username and username.startswith("apikey_"):
            auth_type = "apikey"
            parts = username.split("_", 2)
            api_key_header = parts[1] if len(parts) > 1 else "x-api-key"
        else:
            auth_type = "basic"

        for record in records:
            try:
                url = record.get("url", self.url)
                method = record.get("method", "GET").upper()
                data = record.get("data")
                hdrs = record.get("headers")
                cookies = record.get("cookies")
                timeout = int(record.get("timeout", 15))
                
                # SSL Verify Logic
                verify_input = str(record.get("verify", "true")).lower().strip()
                verify_mode = verify_input in ["true", "1", "yes", "on"]

                # Parse headers JSON if provided
                if hdrs and isinstance(hdrs, str):
                    try:
                        hdrs = json.loads(hdrs)
                    except json.JSONDecodeError:
                        hdrs = {} # Fallback or log error?
                elif not hdrs:
                    hdrs = {}

                # Parse cookies JSON if provided
                if cookies and isinstance(cookies, str):
                    try:
                        cookies = json.loads(cookies)
                    except json.JSONDecodeError:
                        cookies = {}
                elif not cookies:
                    cookies = {}

                # Apply authentication type
                if auth_type == "basic" and username and password:
                    auth = (username, password)
                elif auth_type == "bearer":
                    hdrs["Authorization"] = f"Bearer {password}"
                    auth = None
                elif auth_type == "apikey":
                    hdrs[api_key_header] = password
                    auth = None
                else:
                    auth = None

                # Ensure UTF-8 encoding for data
                if data and isinstance(data, str):
                    data = data.encode("utf-8")

                # Make HTTPS request
                resp = requests.request(
                    method,
                    url,
                    headers=hdrs,
                    cookies=cookies,
                    data=data,
                    auth=auth,
                    timeout=timeout,
                    verify=certifi.where() if verify_mode else False
                )

                # Parse response
                record["status_code"] = resp.status_code
                record["response"] = resp.text
                record["response_headers"] = json.dumps(dict(resp.headers))
                record["ssl_verify"] = verify_mode

            except Exception as e:
                record["error"] = str(e)

            yield record


if __name__ == "__main__":
    dispatch(ReqCommand, sys.argv, sys.stdin, sys.stdout, __name__)
