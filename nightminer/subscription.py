# Subscription state
import time

import struct
import urllib
from binascii import hexlify, unhexlify

from algos.script import scrypt_proof_of_work
from algos.sha256d import sha256d
from algos.utils import swap_endian_word, swap_endian_words
from nightminer.constants import ALGORITHM_SCRYPT, ALGORITHM_SHA256D


class Job(object):
    """Encapsulates a Job from the network and necessary helper methods to mine.

       "If you have a procedure with 10 parameters, you probably missed some."
             ~Alan Perlis
    """

    def __init__(self, job_id, prevhash, coinb1, coinb2, merkle_branches, version, nbits, ntime, target, extranounce1,
                 extranounce2_size, proof_of_work):

        # Job parts from the mining.notify command
        self._job_id = job_id
        self._prevhash = prevhash
        self._coinb1 = coinb1
        self._coinb2 = coinb2
        self._merkle_branches = [b for b in merkle_branches]
        self._version = version
        self._nbits = nbits
        self._ntime = ntime

        # Job information needed to mine from mining.subsribe
        self._target = target
        self._extranounce1 = extranounce1
        self._extranounce2_size = extranounce2_size

        # Proof of work algorithm
        self._proof_of_work = proof_of_work

        # Flag to stop this job's mine coroutine
        self._done = False

        # Hash metrics (start time, delta time, total hashes)
        self._dt = 0.0
        self._hash_count = 0

    # Accessors
    id = property(lambda s: s._job_id)
    prevhash = property(lambda s: s._prevhash)
    coinb1 = property(lambda s: s._coinb1)
    coinb2 = property(lambda s: s._coinb2)
    merkle_branches = property(lambda s: [b for b in s._merkle_branches])
    version = property(lambda s: s._version)
    nbits = property(lambda s: s._nbits)
    ntime = property(lambda s: s._ntime)

    target = property(lambda s: s._target)
    extranounce1 = property(lambda s: s._extranounce1)
    extranounce2_size = property(lambda s: s._extranounce2_size)

    proof_of_work = property(lambda s: s._proof_of_work)

    @property
    def hashrate(self):
        """The current hashrate, or if stopped hashrate for the job's lifetime."""

        if self._dt == 0: return 0.0
        return self._hash_count / self._dt

    def merkle_root_bin(self, extranounce2_bin):
        """Builds a merkle root from the merkle tree"""

        coinbase_bin = unhexlify(self._coinb1) + unhexlify(self._extranounce1) + extranounce2_bin + unhexlify(
            self._coinb2)
        coinbase_hash_bin = sha256d(coinbase_bin)

        merkle_root = coinbase_hash_bin
        for branch in self._merkle_branches:
            merkle_root = sha256d(merkle_root + unhexlify(branch))
        return str(merkle_root)

    def stop(self):
        """Requests the mine coroutine stop after its current iteration."""

        self._done = True

    def mine(self, nounce_start=0, nounce_stride=1):
        """Returns an iterator that iterates over valid proof-of-work shares.

           This is a co-routine; that takes a LONG time; the calling thread should look like:

             for result in job.mine(self):
               submit_work(result)

           nounce_start and nounce_stride are useful for multi-processing if you would like
           to assign each process a different starting nounce (0, 1, 2, ...) and a stride
           equal to the number of processes.
        """

        t0 = time.time()

        # @TODO: test for extranounce != 0... Do I reverse it or not?
        for extranounce2 in range(0, 0x7fffffff):

            # Must be unique for any given job id, according to http://mining.bitcoin.cz/stratum-mining/ but never seems enforced?
            extranounce2_bin = struct.pack('<I', extranounce2)

            merkle_root_bin = self.merkle_root_bin(extranounce2_bin)
            header_prefix_bin = swap_endian_word(self._version) + swap_endian_words(
                self._prevhash) + merkle_root_bin + swap_endian_word(self._ntime) + swap_endian_word(self._nbits)
            for nounce in range(nounce_start, 0x7fffffff, nounce_stride):
                # This job has been asked to stop
                if self._done:
                    self._dt += (time.time() - t0)
                    raise StopIteration()

                # Proof-of-work attempt
                nounce_bin = struct.pack('<I', nounce)

                pow = self.proof_of_work(header_prefix_bin + str(nounce_bin))[::-1]

                # pow2 = pow[:-2]
                # print(pow, pow2)
                pow = ''.join(hex(ord(c))[2:] for c in pow)
                print(pow, self.target)

                # Did we reach or exceed our target?
                if pow <= self.target:
                    result = dict(
                        job_id=self.id,
                        extranounce2=hexlify(extranounce2_bin),
                        ntime=str(self._ntime),  # Convert to str from json unicode
                        nounce=hexlify(nounce_bin[::-1])
                    )
                    self._dt += (time.time() - t0)

                    yield result

                    t0 = time.time()

                self._hash_count += 1

    def __str__(self):
        return '<Job id=%s prevhash=%s coinb1=%s coinb2=%s merkle_branches=%s version=%s nbits=%s ntime=%s target=%s extranounce1=%s extranounce2_size=%d>' % (
            self.id, self.prevhash, self.coinb1, self.coinb2, self.merkle_branches, self.version, self.nbits,
            self.ntime,
            self.target, self.extranounce1, self.extranounce2_size)


class Subscription(object):
    """Encapsulates the Subscription state from the JSON-RPC server"""

    # Subclasses should override this
    def ProofOfWork(header):
        raise Exception('Do not use the Subscription class directly, subclass it')

    class StateException(Exception):
        pass

    def __init__(self):
        self._id = None
        self._difficulty = None
        self._extranounce1 = None
        self._extranounce2_size = None
        self._target = None
        self._worker_name = None

        self._mining_thread = None

    # Accessors
    id = property(lambda s: s._id)
    worker_name = property(lambda s: s._worker_name)

    difficulty = property(lambda s: s._difficulty)
    target = property(lambda s: s._target)

    extranounce1 = property(lambda s: s._extranounce1)
    extranounce2_size = property(lambda s: s._extranounce2_size)

    def set_worker_name(self, worker_name):
        if self._worker_name:
            # raise self.StateException('Already authenticated as %r (requesting %r)' % (self._username, username))
            raise self.StateException('Already authenticated')

        self._worker_name = worker_name

    def _set_target(self, target):
        self._target = '%064x' % target

    def set_difficulty(self, difficulty):
        if difficulty < 0: raise self.StateException('Difficulty must be non-negative')

        # Compute target
        if difficulty == 0:
            target = 2 ** 256 - 1
        else:
            target = min(int((0xffff0000 * 2 ** (256 - 64) + 1) / difficulty - 1 + 0.5), 2 ** 256 - 1)

        self._difficulty = difficulty
        self._set_target(target)

    def set_subscription(self, subscription_id, extranounce1, extranounce2_size):
        if self._id is not None:
            raise self.StateException('Already subscribed')

        self._id = subscription_id
        self._extranounce1 = extranounce1
        self._extranounce2_size = extranounce2_size

    def create_job(self, job_id, prevhash, coinb1, coinb2, merkle_branches, version, nbits, ntime):
        """Creates a new Job object populated with all the goodness it needs to mine."""

        if self._id is None:
            raise self.StateException('Not subscribed')

        return Job(
            job_id=job_id,
            prevhash=prevhash,
            coinb1=coinb1,
            coinb2=coinb2,
            merkle_branches=merkle_branches,
            version=version,
            nbits=nbits,
            ntime=ntime,
            target=self.target,
            extranounce1=self._extranounce1,
            extranounce2_size=self.extranounce2_size,
            proof_of_work=self.ProofOfWork
        )

    def __str__(self):
        return '<Subscription id=%s, extranounce1=%s, extranounce2_size=%d, difficulty=%d worker_name=%s>' % (
            self.id, self.extranounce1, self.extranounce2_size, self.difficulty, self.worker_name)


class SubscriptionScrypt(Subscription):
    """Subscription for Scrypt-based coins, like Litecoin."""

    ProofOfWork = lambda s, h: (scrypt_proof_of_work(h))

    def _set_target(self, target):
        # Why multiply by 2**16? See: https://litecoin.info/Mining_pool_comparison
        self._target = '%064x' % (target << 16)


class SubscriptionSHA256D(Subscription):
    """Subscription for Double-SHA256-based coins, like Bitcoin."""

    ProofOfWork = sha256d


# Maps algorithms to their respective subscription objects
SubscriptionByAlgorithm = {ALGORITHM_SCRYPT: SubscriptionScrypt, ALGORITHM_SHA256D: SubscriptionSHA256D}