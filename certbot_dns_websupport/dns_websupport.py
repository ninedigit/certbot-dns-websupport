"""

// TODO: Info

WebSupport API: https://rest.websupport.sk/docs/v1.intro
Inspired by: https://github.com/m42e/certbot-dns-ispconfig/blob/master/certbot_dns_ispconfig/dns_ispconfig.py

"""
import logging
import json
import hmac
import hashlib
import time
import requests
import base64
import zope.interface

from typing import Any, Callable, Optional, Tuple
from datetime import datetime, timezone
from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common
from requests import Request, Session

logger = logging.getLogger(__name__)

@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for WebSupport.sk

    This Authenticator uses the WebSupport API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record (if you are ' + \
                  'using WebSupport for DNS).'

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.credentials: Optional[CredentialsConfiguration] = None

    # @classmethod
    # def add_parser_arguments(cls, add):
    #     super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=60)
    #     add('credentials', help='WebSupport credentials INI file.')

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None],
                             default_propagation_seconds: int = 120) -> None:
        super().add_parser_arguments(add, default_propagation_seconds)
        add('credentials', help='WebSupport credentials INI file.')

    def more_info(self):
        return ('This plugin configures a DNS TXT record to respond to a '
                'dns-01 challenge using the WebSupport API.')

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'WebSupport credentials INI file',
            {
                'api_key': 'Key to access the WebSupport API',
                'secret': 'Secret to access the WebSupport API',
            }
        )

    def _perform(self, domain, validation_name, validation) -> None:
        return self._get_websupport_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation) -> None:
        return self._get_websupport_client().del_txt_record(domain, validation_name, validation)

    def _get_websupport_client(self) -> "_WebSupportClient":
        if not self.credentials:  # pragma: no cover
            raise errors.Error("Plugin has not been prepared.")

        return _WebSupportClient(self.credentials.conf('api_key'), self.credentials.conf('secret'))

class _WebSupportClient:
    """
    Encapsulates all communication with the WebSupport API.
    """

    _default_txt_record_note = "Created using Certbot's DNS WebSupport plugin."

    def __init__(self, api_key: str, secret: str) -> None:
        self.api_key = api_key
        self.secret = secret

    def add_txt_record(self, domain_name: str, full_record_name: str, record_content: str):
        """
        Add a TXT record using the supplied information.
        :param str domain_name: The domain to use to look up the managed zone, e.g. subdomain.example.com.
        :param str full_record_name: The record name (typically beginning with '_acme-challenge.'), e.g. _acme-challenge.subdomain.example.com.
        :param str record_content: The record content (typically the challenge validation), e.g. tz01CVeHbasRKhBigGxADzqPTIIh1gBZffcHEmn-oFI.
        :raises errors.PluginError: if an error occurs communicating with the DNS Provider API
        """

        logger.debug(f"Invoked add_txt_record('{domain_name}', '{full_record_name}', '{record_content}')")

        zone_id, zone_name = self._get_managed_zone(domain_name)
        record_name = self._get_record_name(zone_name, full_record_name)
        
        data = { "type": "TXT", "name": record_name, "content": record_content, "ttl": 600, "note": self._default_txt_record_note }
        result = self._api_request("POST", "/v1/user/self/zone/" + zone_name + "/record", data)["item"]
    
    def del_txt_record(self, domain_name: str, full_record_name: str, record_content: str):
        zone_id, zone_name = self._get_managed_zone(domain_name)
        record_name = self._get_record_name(zone_name, full_record_name)
        existing_record = self._find_first_record_id(zone_name, "TXT", record_name, record_content = record_content, record_note = self._default_txt_record_note)

        if existing_record is not None:
            logger.debug(f"Removing TXT record with ID {str(existing_record['id'])}")
            self._delete_record(zone_name, existing_record["id"])

    def _update_txt_record_content(self, zone_name: str, record_id: int, record_content: str):
        return self._api_request("PUT", "/v1/user/self/zone/" + zone_name + "/record/" + str(record_id), { "content": record_content })

    def _delete_record(self, zone_name: str, record_id: int):
        return self._api_request("DELETE", "/v1/user/self/zone/" + zone_name + "/record/" + str(record_id))
    
    def _get_record_name(self, zone_name: str, record_name: str):
        if record_name.endswith("." + zone_name):
            return record_name[0:len(record_name) - len(zone_name) - 1]
        return None

    def _find_first_record_id(self, zone_name: str, record_type: str, record_name: str, record_content = None, record_note = None):
        logger.debug(f"Invoked _find_first_record_id('{zone_name}', '{record_type}', '{record_name}', '{record_content}', '{record_note}')")
        records = self._api_request("GET", "/v1/user/self/zone/" + zone_name + "/record")["items"]

        for record in records:
            if record["type"] == record_type and record["name"] == record_name:
                if isinstance(record_content, str) and record["content"] != record_content:
                    continue
                if isinstance(record_note, str) and record["note"] != record_note:
                    continue
                return record
                break
        
        return None

    def _get_managed_zone(self, domain_name: str) -> Tuple[int, str]:
        """
        Finds the managed zone ID and name for given domain name.

        :param str domain_name: The domain for which to find the managed zone, e.g. subdomain.example.com.
        :returns: Tuplne with zone ID and name, if found.
        :rtype: Tuple[int, str]
        :raises certbot.errors.PluginError: If there was a problem getting zones.
        """
        base_domain_name_gueses = dns_common.base_domain_name_guesses(domain_name)
        zones = self._api_request("GET", "/v1/user/self/zone")["items"]

        for base_domain_name in base_domain_name_gueses:
           for zone in zones:
            if base_domain_name == zone["name"]:
                return zone["id"], zone["name"]

        raise errors.PluginError(f"Unable to determine zone name from {domain_name}")

    def _api_request(self, method: str, path: str, data = None):
        timestamp = int(time.time())
        canonicalRequest = "%s %s %s" % (method, path, timestamp)
        signature = hmac.new(bytes(self.secret, 'UTF-8'), bytes(canonicalRequest, 'UTF-8'), hashlib.sha1).hexdigest()

        headers = {
            "Accept": "application/json",
            "Date": datetime.fromtimestamp(timestamp, timezone.utc).isoformat()
        }

        if data is not None:
            headers["Content-Type"] = "application/json"

        url = "https://rest.websupport.sk"
        query = "" # query part is optional and may be empty
        requestUrl = "%s%s%s" % (url, path, query)

        # https://requests.readthedocs.io/en/latest/api/#requests.request
        response = requests.request(method, requestUrl, json=data, headers=headers, auth=(self.api_key, signature))

        if response.status_code >= 400:
            raise errors.PluginError(f"An HTTP error '{response.status_code}' has occured for {method} {requestUrl} {data}")
            
        try:
            result = response.json()
        except json.decoder.JSONDecodeError:
            raise errors.PluginError(f"API respond with non JSON result: {response.text}")

        # GET requests does not have status
        if "status" in result:
            if result["status"] == "error":
                raise errors.PluginError(f"API respond with errors: {json.dumps(result['errors'])}")
        
        return result