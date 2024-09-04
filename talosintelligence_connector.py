#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals
import os

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom_common.install_info import is_dev_env

from talosintelligence_consts import *

import requests
import json
from bs4 import BeautifulSoup
import tempfile
import httpx
import ipaddress
import time
import random


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class TalosIntelligenceConnector(BaseConnector):

    def __init__(self):
        super(TalosIntelligenceConnector, self).__init__()

        self._state = None

        self._base_url = None
        self._cert = None
        self._key = None

        self._appinfo = None
        self._catalog_id = 2

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Empty response and no information in the header"
            ), None
        )

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace(u'{', '{{').replace(u'}', '}}')
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))
                ), None
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace(u'{', '{{').replace(u'}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        retryable_error_codes = {2, 4, 8, 9, 13, 14}

        if r.headers.get('grpc-status', 0) in retryable_error_codes:
            return action_result.set_status(
                    phantom.APP_ERROR, "Got retryable grpc-status of {0} with message {1}".format(r.headers['grpc-status'], r.headers.get('grpc-message', "Error"))
                ), r

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace('{', '{{').replace('}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        config = self.get_config()

        resp_json = None

        # Create a URL to connect to
        url = self._base_url + endpoint

        delay = 0.25
        for i in range(MAX_CONNECTION_RETIRIES):
            try:
                request_func = getattr(self.client, method)
                r = request_func(
                    url,
                    **kwargs
                )
            except Exception as e:
                self.debug_print(f"Retrying to establish connection to the server for the {i + 1} time")
                jittered_delay = random.uniform(delay * 0.9, delay * 1.1)
                time.sleep(jittered_delay)
                delay = min(delay * 2, 256)

                with tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix="test") as temp_file:
                    cert = f"-----BEGIN CERTIFICATE-----\n{self._cert}\n-----END CERTIFICATE-----\n-----BEGIN RSA PRIVATE KEY-----\n{self._key}\n-----END RSA PRIVATE KEY-----\n"
                    temp_file.write(cert)
                    temp_file.seek(0)  # Move the file pointer to the beginning for reading
                    temp_file_path = temp_file.name  # Get the name of the temporary file
                self.client = httpx.Client(http2=True, verify=config.get('verify_server_cert', False), cert=temp_file_path)

                if os.path.exists(temp_file_path):
                    os.remove(temp_file_path)

                if i == MAX_CONNECTION_RETIRIES - 1:
                    return RetVal(
                        action_result.set_status(
                            phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))
                        ), resp_json
                    )

        return self._process_response(r, action_result)

    def _make_rest_call_helper(self, *args, **kwargs):
        request_delay = 0.25
        for i in range(MAX_REQUEST_RETRIES):
            ret_val, response = self._make_rest_call(*args, **kwargs)
            if phantom.is_fail(ret_val) and response:
                time.sleep(request_delay)
                request_delay *= 2
            else:
                break

        return ret_val, response

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Connecting to endpoint")

        ret_val, response = self._make_rest_call_helper(
            ENDPOINT_QUERY_AUP_CAT_MAP, action_result, "post", json={"app_info": self._appinfo}
        )

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        self.save_progress("Received Metadata")
        self.save_progress("Test Connectivity Passed")

        self._state = {}
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_ip_reputation(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        ip = param['ip']

        try:
            ip_addr = ipaddress.ip_address(ip)
            is_ipv4 = True if isinstance(ip_addr, ipaddress.IPv4Address) else False
            big_endian = int(ip_addr)
        except Exception as exc:
            return action_result.set_status(phantom.APP_ERROR, f"Please provide a valid IP Address. Error: {exc}")

        endpoint = {}
        if is_ipv4:
            endpoint["ipv4_addr"] = big_endian
        else:
            endpoint["ipv6_addr"] = big_endian

        payload = {
            "urls": { "endpoint": [endpoint]},
            "app_info": self._appinfo
        }

        ret_val = self._query_reputation(action_result, payload, ip)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        summary = action_result.update_summary({})
        summary["Message"] = "IP successfully queried"
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_domain_reputation(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        domain = param['domain']
        ips = param.get("ips", "")
        ips_list = [item.strip() for item in ips.split(',') if item.strip()]
        url_entry = {"raw_url": domain}

        endpoints = []
        for ip in ips_list:
            try:
                ip_addr = ipaddress.ip_address(ip)
                big_endian = int(ip_addr)
                endpoints.append({"ipv4_addr": big_endian})
            except Exception as exc:
                self.debug_print(f"{ip} is not a valid ip address got. Error: {exc}")

        if endpoints:
            url_entry["endpoint"] = endpoints

        payload = {
            "urls": [],
            "app_info": self._appinfo
        }
        payload["urls"].append(url_entry)

        ret_val = self._query_reputation(action_result, payload, domain)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        summary = action_result.update_summary({})
        summary["Message"] = "Domain successfully queried"
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_url_reputation(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        url = param['url']
        ips = param.get("ips", "")
        ips_list = [item.strip() for item in ips.split(',') if item.strip()]
        url_entry = {"raw_url": url}

        endpoints = []
        for ip in ips_list:
            try:
                ip_addr = ipaddress.ip_address(ip)
                big_endian = int(ip_addr)
                endpoints.append({"ipv4_addr": big_endian})
            except Exception as exc:
                self.debug_print(f"{ip} is not a valid ip address. Error: {exc}")

        if endpoints:
            url_entry["endpoint"] = endpoints

        payload = {
            "urls": [],
            "app_info": self._appinfo
        }
        payload["urls"].append(url_entry)

        ret_val = self._query_reputation(action_result, payload, url)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        summary = action_result.update_summary({})
        summary["Message"] = "URL successfully queried"
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_domain_enrichment(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        domain = param['domain']
        response_type = param.get("response_type", "Context Tags")
        endpoint = ENDPOINT_ENRICH_DOMAIN

        if response_type == "STIX":
            endpoint = ENDPOINT_ENRICH_DOMAIN_STIX

        payload = {
            "domain": domain,
            "app_info": self._appinfo
        }

        ret_val, response = self._make_rest_call_helper(
            endpoint, action_result, method="post", json=payload
        )
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if response_type == "STIX":
            self._process_response_stix(response, action_result)
        else:
            self._process_taxonomy(response, action_result)

        summary = action_result.update_summary({})
        summary["Message"] = "Enrichment results for domain retrieved"
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_url_enrichment(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        url = param['url']
        response_type = param.get("response_type", "Context Tags")
        endpoint = ENDPOINT_ENRICH_URL

        if response_type == "STIX":
            endpoint = ENDPOINT_ENRICH_URL_STIX

        payload = {
            "url": {"raw_url": url},
            "app_info": self._appinfo
        }

        ret_val, response = self._make_rest_call_helper(
            endpoint, action_result, method="post", json=payload
        )
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if response_type == "STIX":
            self._process_response_stix(response, action_result)
        else:
            ret_val = self._process_taxonomy(response, action_result)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

        summary = action_result.update_summary({})
        summary["Message"] = "Enrichment results for url retrieved"
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_ip_enrichment(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        ip = param['ip']
        response_type = param.get("response_type", "Context Tags")
        endpoint = ENDPOINT_ENRICH_IP

        if response_type == "STIX":
            endpoint = ENDPOINT_ENRICH_IP_STIX

        try:
            ip_addr = ipaddress.ip_address(ip)
            big_endian = int(ip_addr)
        except Exception as exc:
            return action_result.set_status(phantom.APP_ERROR, f"Please provide a valid IP Address. Error: {exc}")

        payload = {
            "endpoint": {"ipv4_addr": big_endian},
            "app_info": self._appinfo
        }

        ret_val, response = self._make_rest_call_helper(
            endpoint, action_result, method="post", json=payload
        )
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if response_type == "STIX":
            self._process_response_stix(response, action_result)
        else:
            ret_val = self._process_taxonomy(response, action_result)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

        summary = action_result.update_summary({})
        summary["Message"] = "Enrichment results for ip retrieved"
        return action_result.set_status(phantom.APP_SUCCESS)

    def _process_response_stix(self, response, action_result):
        self.debug_print("stix response jsonn final")
        data = response.get("json", {})
        stix_data = json.loads(data)
        self.debug_print(stix_data)
        for obj in stix_data.get('objects', []):
            # obj_type = obj.get("attack-pattern")
            action_result.add_data(obj)
            self.debug_print(obj)
        return phantom.APP_SUCCESS

    def _process_taxonomy(self, response, action_result):
        new_taxonomy_fetched = False
        taxonomy_ret_val, taxonomy = self._fetch_taxonomy(action_result)
        if phantom.is_fail(taxonomy_ret_val):
            return action_result.get_status()

        self.debug_print("processing tax")
        self.debug_print(response)
        response_taxonomy_map_version = response["taxonomy_map_version"]

        if response_taxonomy_map_version > self._state["taxonomy_version"]:
            taxonomy_ret_val, taxonomy = self._fetch_taxonomy(action_result, allow_cache=False)

        if phantom.is_fail(taxonomy_ret_val) or "context_tags" not in response:
            return action_result.get_status()

        for tag in response["context_tags"]:
            tax_id = str(tag["taxonomy_id"])
            entry_id = str(tag["taxonomy_entry_id"])

            if tax_id != MITRE_ATTACK_TAX_ID or tax_id not in taxonomy["taxonomies"]:
                # currently enrichment is only supported for MITRE ATTACKs
                continue

            if not taxonomy["taxonomies"][tax_id]["is_avail"]:
                if taxonomy["taxonomies"][tax_id]["vers_avail"]["starting"] > taxonomy["taxonomies"][tax_id]["vers_avail"]["ending"] and not new_taxonomy_fetched:
                    taxonomy_ret_val, taxonomy = self._fetch_taxonomy(action_result, allow_cache=False)
                    new_taxonomy_fetched = True
                    if not taxonomy["taxonomies"][tax_id]["is_avail"]:
                        # even after fetching the taxonomy we're looking for isn't available
                        continue
                else:
                    continue

            category = taxonomy["taxonomies"][tax_id]["name"]["en-us"]["text"]
            name = taxonomy["taxonomies"][tax_id]["entries"][entry_id]["name"]["en-us"]["text"]
            description = taxonomy["taxonomies"][tax_id]["entries"][entry_id]["description"]["en-us"]["text"]

            output = {}
            output["category"] = category
            output["name"] = name
            output["description"] = description
            action_result.add_data(output)

        return phantom.APP_SUCCESS

    def _query_reputation(self, action_result, payload, observable=None):
        new_taxonomy_fetched = False

        taxonomy_ret_val, taxonomy = self._fetch_taxonomy(action_result)

        if phantom.is_fail(taxonomy_ret_val):
            return action_result.get_status()

        # make rest call
        ret_val, response = self._make_rest_call_helper(
            ENDPOINT_QUERY_REPUTATION_V3, action_result, method="post", json=payload
        )
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        response_taxonomy_map_version = response["taxonomy_map_version"]

        if response_taxonomy_map_version > self._state["taxonomy_version"]:
            new_taxonomy_fetched = True
            taxonomy_ret_val, taxonomy = self._fetch_taxonomy(action_result, allow_cache=False)

        if phantom.is_fail(taxonomy_ret_val) or "results" not in response:
            return action_result.get_status()

        threat_level = ""
        threat_categories = {}
        aup_categories = {}

        for result in response["results"]:
            for url_result in result["results"]:
                for tag in url_result["context_tags"]:
                    tax_id = str(tag["taxonomy_id"])
                    entry_id = str(tag["taxonomy_entry_id"])

                    if tax_id not in taxonomy["taxonomies"]:
                        continue

                    if not taxonomy["taxonomies"][tax_id]["is_avail"]:
                        if taxonomy["taxonomies"][tax_id]["vers_avail"]["starting"] > taxonomy["taxonomies"][tax_id]["vers_avail"]["ending"] and not new_taxonomy_fetched:
                            taxonomy_ret_val, taxonomy = self._fetch_taxonomy(action_result, allow_cache=False)
                            new_taxonomy_fetched = True
                            if not taxonomy["taxonomies"][tax_id]["is_avail"]:
                                # even after fetching the taxonomy we're looking for isn't available
                                continue
                        else:
                            continue

                    category = taxonomy["taxonomies"][tax_id]["name"]["en-us"]["text"]
                    name = taxonomy["taxonomies"][tax_id]["entries"][entry_id]["name"][
                        "en-us"
                    ]["text"]
                    description = taxonomy["taxonomies"][tax_id]["entries"][entry_id][
                        "description"
                    ]["en-us"]["text"]

                    if category == "Threat Levels":
                        threat_level = name
                    elif category == "Threat Categories":
                        threat_categories[name] = description
                    elif category == "Acceptable Use Policy Categories":
                        aup_categories[name] = description

            output = {}
            output["Observable"] = observable
            output["Threat_Level"] = threat_level
            output["Threat_Categories"] = ", ".join(list(threat_categories.keys()))
            output["AUP"] = ", ".join(list(aup_categories.keys()))

            action_result.add_data(output)

            return phantom.APP_SUCCESS

    def _fetch_taxonomy(self, action_result, allow_cache=True):

        payload = {
            "app_info": self._appinfo
        }

        if "taxonomy" in self._state and allow_cache:
            return 1, self._state["taxonomy"]

        ret_val, response = self._make_rest_call_helper(
            ENDPOINT_QUERY_TAXONOMIES, action_result, method="post", json=payload
        )
        self.debug_print("fetching taxonomyyy")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        taxonomy = response["catalogs"][str(self._catalog_id)]

        self._state = {"taxonomy": taxonomy, "taxonomy_version": response["version"]}

        return ret_val, taxonomy

    def _handle_domain_prevalence(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        domains = param["domains"]
        domains_list = [item.strip() for item in domains.split(',') if item.strip()]
        first_seen = param.get("first_seen")
        last_seen = param.get("last_seen")

        payload = {
            "domain": domains_list,
            "app_info": self._appinfo
        }

        if first_seen:
            payload["first_seen"] = first_seen

        if last_seen:
            payload["last_seen"] = last_seen

        ret_val, response = self._make_rest_call_helper(
            ENDPOINT_DOMAIN_PREVALENCE, action_result, method="post", json=payload
        )
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        data = response["responses"]
        for domain in data:
            data[domain]["domain"] = domain
            action_result.add_data(data[domain])
        datasets_type = type(data["cisco.com"]["datasets"])
        self.debug_print(f"type is {datasets_type}")

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_ip_prevalence(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        ips = param["ips"]
        ips_list = [item.strip() for item in ips.split(',') if item.strip()]
        first_seen = param.get("first_seen")
        last_seen = param.get("last_seen")
        ips_in_request = []

        try:
            for ip in ips_list:
                ip_addr = ipaddress.ip_address(ip)
                ips_in_request.append(int(ip_addr))
        except Exception as exc:
            return action_result.set_status(phantom.APP_ERROR, f"Please provide a valid IP Address. Error: {exc}")

        payload = {
            "endpoint": {"ipv4_addr": ips_in_request},
            "app_info": self._appinfo
        }

        if first_seen:
            payload["first_seen"] = first_seen

        if last_seen:
            payload["last_seen"] = last_seen

        ret_val, response = self._make_rest_call_helper(
            ENDPOINT_DOMAIN_PREVALENCE, action_result, method="post", json=payload
        )
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        data = response["responses"]
        action_result.add_data(data)

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'ip_reputation':
            ret_val = self._handle_ip_reputation(param)

        elif action_id == 'domain_reputation':
            ret_val = self._handle_domain_reputation(param)

        elif action_id == 'url_reputation':
            ret_val = self._handle_url_reputation(param)

        elif action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'ip_enrichment':
            ret_val = self._handle_ip_enrichment(param)

        elif action_id == 'domain_enrichment':
            ret_val = self._handle_domain_enrichment(param)

        elif action_id == 'url_enrichment':
            ret_val = self._handle_url_enrichment(param)

        elif action_id == 'domain_prevalence':
            ret_val = self._handle_domain_prevalence(param)

        elif action_id == 'ip_prevalence':
            ret_val = self._handle_ip_prevalence(param)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        def insert_newlines(string, every=64):
            return '\n'.join(string[i:i + every] for i in range(0, len(string), every))

        self._base_url = config['base_url']
        self._cert = insert_newlines(config["certificate"])
        self._key = insert_newlines(config["key"])

        self._appinfo = {
            "product_family": "splunk",
            "product_id": "soar",
            "device_id": self.get_product_installation_id(),
            "product_version": self.get_product_version(),
            "perf_testing": True,
        }
        if is_dev_env:
            self._appinfo["perf_testing"] = True

        with tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix="test") as temp_file:
            cert = f"-----BEGIN CERTIFICATE-----\n{self._cert}\n-----END CERTIFICATE-----\n-----BEGIN RSA PRIVATE KEY-----\n{self._key}\n-----END RSA PRIVATE KEY-----\n"

            temp_file.write(cert)
            temp_file.seek(0)  # Move the file pointer to the beginning for reading
            temp_file_path = temp_file.name  # Get the name of the temporary file

        # exceptions shouldn't really be thrown here because most network related disconnections will happen when a request is sent
        try:
            self.client = httpx.Client(http2=True, verify=config.get('verify_server_cert', False), cert=temp_file_path)
        except Exception as e:
            self.debug_print(f"Could not connect to server because of {e}")
            if os.path.exists(temp_file_path):
                os.remove(temp_file_path)
            return phantom.APP_ERROR

        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)
        return phantom.APP_SUCCESS

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    import argparse

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = TalosIntelligenceConnector._get_phantom_base_url() + '/login'

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = TalosIntelligenceConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
