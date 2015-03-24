"""Network Module."""
import copy
import httplib
import logging
import sys
import time

import M2Crypto
import requests

from letsencrypt.acme import jose
from letsencrypt.acme import messages
from letsencrypt.acme import messages2
from letsencrypt.acme.jose import util as jose_util

from letsencrypt.client import errors
err = errors.LetsEncryptClientError


logging.getLogger("requests").setLevel(logging.WARNING)

class Resource(jose.ImmutableMap):
    __slots__ = ('body', 'location')


class Network(object):
    """Class for communicating with ACME servers.

    :ivar str server_url: Full URL of the ACME service

    """
    def __init__(self, key_pem):
        """Initialize Network instance.

        :param str key: key to sign each message in PEM form

        """
        self.key = jose.JWKRSA.load(key_pem)
        self.alg = jose.RS256
        # self.next_url = "/acme/new-authz"

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

    # def send(self, msg, headers, resource):
    #     """Send ACME message to server.
    #
    #     :param msg: ACME message.
    #     :type msg: :class:`letsencrypt.acme.messages.Message`
    #
    #     :param headers: headers
    #
    #     :param resource: path of RESTful api call
    #
    #     :returns: tuple of the form (Server response message, link to next resource)
    #     :rtype: `tuple` of class:`letsencrypt.acme.messages.Message`, string
    #
    #     :raises letsencrypt.acme.errors.ValidationError: if `msg` is not
    #         valid serializable ACME JSON message.
    #     :raises err: in case of connection error
    #         or if response from server is not a valid ACME message.
    #
    #     """
    #     h2 = copy.copy(headers)
    #     h2.update({"Content-Type": "application/json"})
    #
    #     dumps = msg.json_dumps()
    #     # logging.debug('Serialized JSON: %s', dumps)
    #     signed_req = jose.JWS.sign(
    #         payload=dumps, key=key, alg=jose.RS256).json_dumps()
    #
    #     try:
    #         response = requests.post(
    #             self.server_url + resource,
    #             data=signed_req,
    #             headers = h2,
    #             # TODO add server cert pinning here
    #             # http://docs.python-requests.org/en/latest/user/advanced/#ssl-cert-verification
    #             verify=True
    #         )
    #     except requests.exceptions.RequestException as error:
    #         raise err('Sending ACME message to server has failed: %s' % error)
    #
    #     # next_link = self.extract_link_headers(response)
    #     next_link = response.links['next']['url']
    #
    #     rtype = response.headers["content-type"]
    #     if rtype == "application/json":
    #         json_string = response.json()
    #     elif rtype == "application/pkix-cert":
    #         # XXX Refactoring advised
    #         # All our plumbing assumes all responses are JSON so for now, bake
    #         # this back into the old Certificate JSON message type
    #         # XXX Fetch chain from Link: and add it...
    #         certobj = {"certificate": response.content}
    #         json_string = json.dumps(certobj)
    #     else:
    #         raise err("Unexpected content type " +
    #               rtype + " in response to " + resource + " message.")
    #
    #     try:
    #         return (messages2.Message.from_json(json_string), next_link)
    #     except jose.DeserializationError as error:
    #         logging.error(json_string)
    #         raise  # TODO


    def send(self, resource, expect="json"):
        """
        :param resource: Resource to send
        :returns: Resource if json,

        """
        dumps = resource.body.json_dumps()
        logging.debug("Serialized JSON: %s", dumps)
        signed_req = jose.JWS.sign(
            payload=dumps, key=self.key, alg=self.alg).json_dumps()
        logging.debug("Serialized JWS: %s", signed_req)

        response = requests.post(resource.location, signed_req)
        logging.debug("Received response %s: %s", response, response.text)

        if (response.status_code == httplib.OK or
            response.status_code == httplib.CREATED):
            pass

        # TODO: server might override NEW_AUTHZ_URI (after new-reg) or
        # NEW_CERTZ_URI (after new-authz) and we should use it
        # instead. Below code only prints the link.
        if "next" in response.links:
            logging.debug("Link (next): %s", response.links["next"]["url"])
        if "up" in response.links:
            logging.debug("Link (up): %s", response.links["up"]["url"])

        rtype = response.headers["content-type"]
        print response.headers
        if rtype == "application/json" or expect == "json":
            return messages2.Resource(
                body=type(resource.body).from_json(response.json()),
                location=response.headers["location"])
        elif rtype == "application/pkix-cert" or expect == "pkix":
            # TODO: Refactoring necessary
            # All our plumbing assumes all responses are JSON so for now, bake
            # this back into the old Certificate JSON message type
            # XXX Fetch chain from Link: and add it...
            print response.content
            return messages.Certificate(
                certificate=jose_util.ComparableX509(
                    M2Crypto.X509.load_request_der_string(response.content)))
        # Reponse to challenge
        else:
            print response.status_code
            assert(response.status_code == httplib.ACCEPTED)

    def wait_for_auth(self, url):
        for i in xrange(5):
            # TODO: wait for valid response
            print requests.get(url).content
            time.sleep(3)

    # def send_and_receive_expected(self, msg, expected):
    #     """Send ACME message to server and return expected message.
    #
    #     :param msg: ACME message.
    #     :type msg: :class:`letsencrypt.acme.Message`
    #
    #     :returns: ACME response message of expected type.
    #     :rtype: :class:`letsencrypt.acme.messages.Message`
    #
    #     :raises err: An exception is thrown
    #
    #     """
    #     dest = self.msgDestinations[msg.typ]
    #     response, next_link = self.send(msg, path)
    #     self.next_link
    #     # TODO check that next_list is as expected, or follow it
    #     return self.is_expected_msg(response, expected)


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
