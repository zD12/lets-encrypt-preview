"""Network Module."""
import logging
import sys
import time

import requests

from letsencrypt.acme import jose
from letsencrypt.acme import messages

from letsencrypt.client import errors
err = errors.LetsEncryptClientError


logging.getLogger("requests").setLevel(logging.WARNING)


class Network(object):
    """Class for communicating with ACME servers.

    :ivar str server_url: Full URL of the ACME service

    """
    def __init__(self, server):
        """Initialize Network instance.

        :param str server: ACME (CA) server[:port]

        """
        self.server_url = "https://%s/acme/" % server
        self.next_url = "/acme/new-authz"

    def extract_link_headers(self, response):
        """ requests module merges repeated Link: headers; unmerge them and
            split out their annotations

        :param msg: server response
        :type msg: :class:`requests.models.Response`
        """
        link_headers = [
            lh.split(";") # each link header in segments
            for lh in response.headers["link"].split(",")
        ]
        next_links = [s[0] for s in link_headers if 'rel="next"' in s]

        if len(next_links) != 1:
            raise err('Did not find Link: ...;rel="next" in Link: '
                  + response.headers["link"])
        return next_links[0]

    def send(self, msg, resource):
        """Send ACME message to server.

        :param msg: ACME message.
        :type msg: :class:`letsencrypt.acme.messages.Message`

        :returns: tuple of the form (Server response message, link to next resource)
        :rtype: `tuple` of class:`letsencrypt.acme.messages.Message`, string

        :raises letsencrypt.acme.errors.ValidationError: if `msg` is not
            valid serializable ACME JSON message.
        :raises err: in case of connection error
            or if response from server is not a valid ACME message.

        """
        try:
            response = requests.post(
                self.server_url + resource,
                data=msg.json_dumps(),
                headers={"Content-Type": "application/json"},
                # TODO add server cert pinning here
                # http://docs.python-requests.org/en/latest/user/advanced/#ssl-cert-verification
                verify=True
            )
        except requests.exceptions.RequestException as error:
            raise err('Sending ACME message to server has failed: %s' % error)

        rtype = headers["content-type"]
        if rtype == "application/json":
            json_string = response.json()
        elif rtype == "application/pkix-cert":
            # XXX Refactoring advised
            # All our plumbing assumes all responses are JSON so for now, bake
            # this back into the old Certificate JSON message type
            # XXX Fetch chain from Link: and add it...
            certobj = { "certificate" : response.content}
            json_string = json.dumps(certobj)
        else:
            raise err("Unexpected content type " +
                  rtype + " in response to " + resource + " message.")

        try:
            return messages.Message.from_json(json_string)
        except jose.DeserializationError as error:
            logging.error(json_string)
            raise  # TODO

    # RESTified path matchers, indexed by message type...
    msgDestinations = {
        "challengeRequest" : "/acme/new-registration",
        #"challenge"
        #"authorization"
        "authorizationRequest": "/acme/new-authz"
        "certificate"
        "certificateRequest" : "/acme/new-cert",
        "challengeDone" : "/acme/authz", # new since REST
        #"defer"
        #"error"
        #"revocation"
        "revocationRequest" : "/acme/cert/.*"
        # "statusRequest":
    }

    def send_and_receive_expected(self, msg, expected):
        """Send ACME message to server and return expected message.

        :param msg: ACME message.
        :type msg: :class:`letsencrypt.acme.Message`

        :returns: ACME response message of expected type.
        :rtype: :class:`letsencrypt.acme.messages.Message`

        :raises err: An exception is thrown

        """
        dest = self.msgDestinations[msg.typ]
        response, next_link = self.send(msg, path)
        self.next_link
        # TODO check that next_list is as expected, or follow it
        return self.is_expected_msg(response, expected)


    def is_expected_msg(self, response, expected, delay=3, rounds=20):
        """Is response expected ACME message?

        :param response: ACME response message from server.
        :type response: :class:`letsencrypt.acme.messages.Message`

        :param expected: Expected response type.
        :type expected: subclass of :class:`letsencrypt.acme.messages.Message`

        :param int delay: Number of seconds to delay before next round
            in case of ACME "defer" response message.
        :param int rounds: Number of resend attempts in case of ACME "defer"
            response message.

        :returns: ACME response message from server.
        :rtype: :class:`letsencrypt.acme.messages.Message`

        :raises LetsEncryptClientError: if server sent ACME "error" message

        """
        for _ in xrange(rounds):
            if isinstance(response, expected):
                return response
            elif isinstance(response, messages.Error):
                logging.error("%s", response)
                raise err(response.error)
            elif isinstance(response, messages.Defer):
                logging.info("Waiting for %d seconds...", delay)
                time.sleep(delay)
                response = self.send(
                    messages.StatusRequest(token=response.token))
            else:
                logging.fatal("Received unexpected message")
                logging.fatal("Expected: %s", expected)
                logging.fatal("Received: %s", response)
                sys.exit(33)

        logging.error(
            "Server has deferred past the max of %d seconds", rounds * delay)
