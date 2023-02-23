# Development

1. Clone **CertBot** repository:
 - `mkdir .certbot`
 - `$ git clone https://github.com/certbot/certbot`

2. Set up the Python virtual environment that will host your Certbot local instance:
 - `$ python3 .certbot/certbot/tools/venv.py`
 - `$ source .certbot/venv/bin/activate` or (`. .certbot/venv/bin/activate`)

3. Install CertBot plugins: `$ pip3 install -e ./certbot/certbot/examples/plugins/`

4. Install this plugin: `$ pip3 install -e ./` (To uninstall call `$ pip3 uninstall certbot-dns-websupport`)

## Create certificate

1. Get API keys

    Create API keys for WebSupport.sk REST at https://admin.websupport.sk/sk/auth/apiKey

2. Create configuration file

    ```ini
    dns_websupport_api_key=<api_key>
    dns_websupport_secret=<secret>
    ```

3. Generate certificate

    `$ certbot certonly --force-renewal --agree-tos --authenticator dns-websupport --dns-websupport-credentials ./credentials.ini --dns-websupport-propagation-seconds 120 --non-interactive --email info@ninedigit.sk -d 'expose.ninedigit.sk' -d '*.expose.ninedigit.sk' --rsa-key-size 2048`

    Renewal can be tested using
    
    `$ sudo certbot renew --dry-run`

    Certificate can be removed using

    `$ sudo certbot delete --cert-name expose.ninedigit.sk`

# Resources

## Development
- https://eff-certbot.readthedocs.io/en/stable/contributing.html
- https://tharakamd-12.medium.com/writing-your-own-certbot-plugin-for-lets-encrypt-215efb79b950
- https://medium.com/@saurabh6790/generate-wildcard-ssl-certificate-using-lets-encrypt-certbot-273e432794d7

## Management
WebSupport API keys can be managed at https://admin.websupport.sk/sk/auth/apiKey

WebSupport DNS records can be managed at https://admin.websupport.sk/sk/domain/dns/records/