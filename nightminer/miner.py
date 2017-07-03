# Miner client

import logging
import socket
import threading
import time
from urllib import parse

from algos.utils import human_readable_hashrate
from nightminer.client import SimpleJsonRpcClient
from nightminer.constants import ALGORITHM_SCRYPT, VERSION, USER_AGENT, LEVEL_DEBUG, LEVEL_INFO, LEVEL_ERROR
from nightminer.subscription import SubscriptionByAlgorithm


class Miner(SimpleJsonRpcClient):
    """Simple mining client"""

    class MinerWarning(SimpleJsonRpcClient.RequestReplyWarning):
        def __init__(self, message, reply, request=None):
            SimpleJsonRpcClient.RequestReplyWarning.__init__(self, 'Mining Sate Error: ' + message, reply, request)

    class MinerAuthenticationException(SimpleJsonRpcClient.RequestReplyException):
        pass

    def __init__(self, url, username, password, algorithm=ALGORITHM_SCRYPT):
        SimpleJsonRpcClient.__init__(self)

        self._url = url
        self._username = username
        self._password = password

        self._subscription = SubscriptionByAlgorithm[algorithm]()

        self._job = None

        self._accepted_shares = 0

    # Accessors
    url = property(lambda s: s._url)
    username = property(lambda s: s._username)
    password = property(lambda s: s._password)

    # Overridden from SimpleJsonRpcClient
    def handle_reply(self, request, reply):

        # New work, stop what we were doing before, and start on this.
        if reply.get('method') == 'mining.notify':
            if 'params' not in reply or len(reply['params']) != 9:
                raise self.MinerWarning('Malformed mining.notify message', reply)

            (job_id, prevhash, coinb1, coinb2, merkle_branches, version, nbits, ntime, clean_jobs) = reply['params']
            self._spawn_job_thread(job_id, prevhash, coinb1, coinb2, merkle_branches, version, nbits, ntime)

            logging.debug('New job: job_id=%s' % job_id, LEVEL_DEBUG)

        # The server wants us to change our difficulty (on all *future* work)
        elif reply.get('method') == 'mining.set_difficulty':
            if 'params' not in reply or len(reply['params']) != 1:
                raise self.MinerWarning('Malformed mining.set_difficulty message', reply)

            (difficulty,) = reply['params']
            self._subscription.set_difficulty(difficulty)

            logging.debug('Change difficulty: difficulty=%s' % difficulty, LEVEL_DEBUG)

        # This is a reply to...
        elif request:

            # ...subscribe; set-up the work and request authorization
            if request.get('method') == 'mining.subscribe':
                if 'result' not in reply or len(reply['result']) != 3 or len(reply['result'][0]) != 2:
                    raise self.MinerWarning('Reply to mining.subscribe is malformed', reply, request)

                ((mining_notify, subscription_id), extranounce1, extranounce2_size) = reply['result']

                self._subscription.set_subscription(subscription_id, extranounce1, extranounce2_size)

                logging.debug('Subscribed: subscription_id=%s' % subscription_id, LEVEL_DEBUG)

                # Request authentication
                self.send(method='mining.authorize', params=[self.username, self.password])

            # ...authorize; if we failed to authorize, quit
            elif request.get('method') == 'mining.authorize':
                if 'result' not in reply or not reply['result']:
                    raise self.MinerAuthenticationException('Failed to authenticate worker', reply, request)

                worker_name = request['params'][0]
                self._subscription.set_worker_name(worker_name)

                logging.debug('Authorized: worker_name=%s' % worker_name, LEVEL_DEBUG)

            # ...submit; complain if the server didn't accept our submission
            elif request.get('method') == 'mining.submit':
                if 'result' not in reply or not reply['result']:
                    logging.info('Share - Invalid', LEVEL_INFO)
                    raise self.MinerWarning('Failed to accept submit', reply, request)

                self._accepted_shares += 1
                logging.info('Accepted shares: %d' % self._accepted_shares, LEVEL_INFO)

            # ??? *shrug*
            else:
                raise self.MinerWarning('Unhandled message', reply, request)

        # ??? *double shrug*
        else:
            raise self.MinerWarning('Bad message state', reply)

    def _spawn_job_thread(self, job_id, prevhash, coinb1, coinb2, merkle_branches, version, nbits, ntime):
        """Stops any previous job and begins a new job."""

        # Stop the old job (if any)
        if self._job:
            self._job.stop()

        # Create the new job
        self._job = self._subscription.create_job(
            job_id=job_id,
            prevhash=prevhash,
            coinb1=coinb1,
            coinb2=coinb2,
            merkle_branches=merkle_branches,
            version=version,
            nbits=nbits,
            ntime=ntime
        )

        def run(job):
            try:
                for result in job.mine():
                    params = [self._subscription.worker_name] + [result[k] for k in
                                                                 ('job_id', 'extranounce2', 'ntime', 'nounce')]
                    self.send(method='mining.submit', params=params)
                    logging.info("Found share: " + str(params), LEVEL_INFO)
                logging.info("Hashrate: %s" % human_readable_hashrate(job.hashrate), LEVEL_INFO)
            except Exception as e:
                logging.error("ERROR: %s" % e, LEVEL_ERROR)

        thread = threading.Thread(target=run, args=(self._job,))
        thread.daemon = True
        thread.start()

    def serve_forever(self):
        """Begins the miner. This method does not return."""

        # Figure out the hostname and port
        url = parse.urlparse(self.url)
        hostname = url.hostname or ''
        port = url.port or 9333

        logging.info('Starting server on %s:%d' % (hostname, port), LEVEL_INFO)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((hostname, port))
        self.connect(sock)

        self.send(method='mining.subscribe', params=["%s/%s" % (USER_AGENT, '.'.join(str(p) for p in VERSION))])

        # Forever...
        while True:
            time.sleep(10)
