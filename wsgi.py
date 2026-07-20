"""Production WSGI entry point for gunicorn or another WSGI server."""

import os

from web.api import SSLManagerAPI


application = SSLManagerAPI(os.environ.get('SSLMGR_CONFIG')).app
