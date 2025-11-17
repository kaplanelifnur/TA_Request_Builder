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
    method = Option(require=False, default="GET")
    identity = Option(require=False)
    realm = Option(require=False)
    headers = Option(require=False)
    data = Option(require=False)  # 👈 renamed from body
    verify = Option(require=False, default="true")  # user can toggle SSL verification

    def stream(self, records):
        session_key = self.metadata.searchinfo.session_key
        username, password = None, None
        auth_type, api_key_header = None, None

        # Convert verify parameter to boolean
        verify_input = str(self.verify).lower().strip()
        verify_mode = not (verify_input in ["false", "0", "no", "none"])

        # Fetch credentials from Splunk storage
        if self.identity and self.realm:
            service = connect(token=session_key)
            for cred in service.storage_passwords:
                if cred.realm == self.realm and cred.username == self.identity:
                    username = cred.username
                    password = cred.clear_password
                    break

        # Determine auth type
        if username and username.startswith("bearer:"):
            auth_type = "bearer"
        elif username and username.startswith("apikey:"):
            auth_type = "apikey"
            parts = username.split(":", 2)
            api_key_header = parts[1] if len(parts) > 1 else "x-api-key"
        else:
            auth_type = "basic"

        for record in records:
            try:
                url = record.get("url", self.url)
                method = record.get("method", self.method).upper()
                data = record.get("data", self.data)
                hdrs = record.get("headers", self.headers)

                # Parse headers JSON if provided
                if hdrs and isinstance(hdrs, str):
                    hdrs = json.loads(hdrs)
                elif not hdrs:
                    hdrs = {}

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
                    data=data,
                    auth=auth,
                    timeout=15,
                    verify=certifi.where() if verify_mode else False
                )

                # Parse response
                record["status_code"] = resp.status_code
                record["response"] = resp.text[:1000]
                record["ssl_verify"] = verify_mode

            except Exception as e:
                record["error"] = str(e)

            yield record


if __name__ == "__main__":
    dispatch(ReqCommand, sys.argv, sys.stdin, sys.stdout, __name__)
