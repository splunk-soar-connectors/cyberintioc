# Copyright (c) 2025 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#!/usr/bin/python
# -----------------------------------------
# Phantom App Connector python file
# -----------------------------------------

import json
from datetime import datetime, timezone

import phantom.app as phantom
import requests
from bs4 import BeautifulSoup
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from cyberintioc_consts import (
    IOC_ENRICH_DOMAIN_ENDPOINT,
    IOC_ENRICH_IPV4_ENDPOINT,
    IOC_ENRICH_SHA256_ENDPOINT,
    IOC_ENRICH_URL_ENDPOINT,
    IOC_FEED_DAILY_ENDPOINT,
    IOC_FEED_TEST_CONNECTION_ENDPOINT,
)


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class CyberintIocConnector(BaseConnector):
    def __init__(self):
        super().__init__()
        self._state = None
        self._base_url = None
        self._access_token = None
        self._customer_id = None
        self._customer_name = None

    def _get_custom_headers(self):
        app_json = self.get_app_json()
        config = self.get_config()
        return {
            "X-Integration-Type": "Splunk SOAR",
            "X-Integration-Instance-Name": config.get("asset_name"),
            "X-Integration-Instance-Id": str(self.get_asset_id()),
            "X-Integration-Customer-Name": self._customer_name,
            "X-Integration-Version": app_json.get("app_version"),
        }

    def initialize(self):
        self._state = self.load_state()
        config = self.get_config()
        self._base_url = config.get("base_url")
        self._access_token = config.get("access_token")
        self._customer_name = config.get("customer_name")
        return phantom.APP_SUCCESS

    def _process_response(self, r, action_result):
        if hasattr(action_result, "add_debug_data"):
            action_result.add_debug_data({"r_status_code": r.status_code})
            action_result.add_debug_data({"r_text": r.text})
            action_result.add_debug_data({"r_headers": r.headers})

        if "json" in r.headers.get("Content-Type", ""):
            try:
                resp_json = r.json()
            except Exception as e:
                return RetVal(
                    action_result.set_status(phantom.APP_ERROR, f"Unable to parse JSON response. Error: {e}"),
                    None,
                )
            if 200 <= r.status_code < 399:
                return RetVal(phantom.APP_SUCCESS, resp_json)
            message = f"Error from server. Status Code: {r.status_code} Data from server: {r.text}"
            return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

        if "html" in r.headers.get("Content-Type", ""):
            try:
                soup = BeautifulSoup(r.text, "html.parser")
                error_text = "\n".join([x.strip() for x in soup.text.split("\n") if x.strip()])
            except Exception:
                error_text = "Cannot parse error details"
            message = f"Status Code: {r.status_code}. Data from server:\n{error_text}\n"
            return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

        if not r.text:
            if r.status_code == 200:
                return RetVal(phantom.APP_SUCCESS, {})
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"),
                None,
            )

        message = f"Can't process response from server. Status Code: {r.status_code} Data from server: {r.text}"
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        config = self.get_config()
        cookies = {"access_token": self._access_token}
        kwargs["cookies"] = cookies

        headers = self._get_custom_headers()
        if "headers" in kwargs:
            headers.update(kwargs["headers"])
        kwargs["headers"] = headers

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, f"Invalid method: {method}"),
                None,
            )

        url = self._base_url + endpoint
        try:
            r = request_func(url, verify=config.get("verify_server_cert", False), **kwargs)
        except Exception as e:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, f"Error Connecting to server. Details: {e}"),
                None,
            )

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Connecting to endpoint...")
        ret_val, response = self._make_rest_call(IOC_FEED_TEST_CONNECTION_ENDPOINT, action_result, method="get")
        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()
        self.save_progress("Test Connectivity Passed.")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_enrich_sha256(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val, response = self._make_rest_call(f"{IOC_ENRICH_SHA256_ENDPOINT}?value={param['Hash']}", action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_enrich_ipv4(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val, response = self._make_rest_call(f"{IOC_ENRICH_IPV4_ENDPOINT}?value={param['IP']}", action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_enrich_url(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val, response = self._make_rest_call(f"{IOC_ENRICH_URL_ENDPOINT}?value={param['URL']}", action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_enrich_domain(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val, response = self._make_rest_call(f"{IOC_ENRICH_DOMAIN_ENDPOINT}?value={param['Domain']}", action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_on_poll(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        container = {
            "name": f"Cyberint Daily IOC Feed - {today}",
            "source_data_identifier": f"cyberint_ioc_feed_{today}",
        }
        status, message, container_id = self.save_container(container)
        if phantom.is_fail(status):
            self.debug_print(f"Could not create container (likely already exists): {message}")

        if not container_id:
            sdi = f"cyberint_ioc_feed_{today}"
            url = f"{self.get_phantom_base_url()}/rest/container?_filter_source_data_identifier='{sdi}'"
            try:
                r = self._get_requests_session().get(url, verify=False)
                r.raise_for_status()
                data = r.json()
                if data.get("count", 0) > 0:
                    container_id = data["data"][0]["id"]
                else:
                    return action_result.set_status(
                        phantom.APP_ERROR,
                        "Failed to create or find container for IOC feed",
                    )
            except Exception as e:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    f"Failed to create or find container for IOC feed: {e}",
                )

        offset = 0
        limit = 100
        total_iocs = 0
        while True:
            self.save_progress(f"Fetching IOCs, offset: {offset}")
            ioc_args = f"?limit={limit}&offset={offset}&format=json"
            ret_val, iocs = self._make_rest_call(f"{IOC_FEED_DAILY_ENDPOINT}/{today}{ioc_args}", action_result)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            if not iocs:
                break

            for ioc in iocs:
                artifact = {
                    "name": ioc.get("ioc_value"),
                    "cef": {ioc.get("ioc_type"): ioc.get("ioc_value")},
                    "container_id": container_id,
                    "source_data_identifier": ioc.get("id"),
                }
                self.save_artifact(artifact)

            total_iocs += len(iocs)
            offset += limit

        action_result.update_summary({"iocs_ingested": total_iocs})
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        if hasattr(self, "_get_requests_session"):
            self._requests_session = self._get_requests_session()
        ret_val = phantom.APP_SUCCESS
        action_id = self.get_action_identifier()
        self.debug_print("action_id", action_id)

        if action_id == "test_connectivity":
            ret_val = self._handle_test_connectivity(param)
        elif action_id == "enrich_sha256":
            ret_val = self._handle_enrich_sha256(param)
        elif action_id == "enrich_ipv4":
            ret_val = self._handle_enrich_ipv4(param)
        elif action_id == "enrich_url":
            ret_val = self._handle_enrich_url(param)
        elif action_id == "enrich_domain":
            ret_val = self._handle_enrich_domain(param)
        elif action_id == "on_poll":
            ret_val = self._handle_on_poll(param)

        return ret_val

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser()
    parser.add_argument("input_test_json", help="Input Test JSON file")
    args = parser.parse_args()

    with open(args.input_test_json) as f:
        in_json = json.load(f)

    connector = CyberintIocConnector()
    connector.print_progress_message = True

    # Mock the config for local testing
    connector._base_url = in_json["config"].get("base_url")
    connector._access_token = in_json["config"].get("access_token")
    connector._customer_id = in_json["config"].get("customer_id")

    # Mock get_action_identifier
    connector._action_identifier = in_json.get("action")

    ret_val = connector.handle_action(in_json.get("parameters", [{}])[0])
    print(ret_val)

    sys.exit(0)
