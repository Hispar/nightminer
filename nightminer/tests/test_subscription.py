import json

import logging

from algos.script import SCRYPT_LIBRARY
from nightminer.subscription import SubscriptionScrypt


def test_subscription():
    """Test harness for mining, using a known valid share."""

    logging.debug('TEST: Scrypt algorithm = %r' % SCRYPT_LIBRARY)
    logging.debug('TEST: Testing Subscription')

    subscription = SubscriptionScrypt()

    # Set up the subscription
    reply = json.loads(
        '{"error": null, "id": 1, "result": [["mining.notify", "ae6812eb4cd7735a302a8a9dd95cf71f"], "f800880e", 4]}')
    logging.debug('TEST: %r' % reply)
    ((mining_notify, subscription_id), extranounce1, extranounce2_size) = reply['result']
    subscription.set_subscription(subscription_id, extranounce1, extranounce2_size)

    # Set the difficulty
    reply = json.loads('{"params": [32], "id": null, "method": "mining.set_difficulty"}')
    logging.debug('TEST: %r' % reply)
    (difficulty,) = reply['params']
    subscription.set_difficulty(difficulty)

    # Create a job
    reply = json.loads(
        '{"params": ["1db7", "0b29bfff96c5dc08ee65e63d7b7bab431745b089ff0cf95b49a1631e1d2f9f31", "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2503777d07062f503253482f0405b8c75208", "0b2f436f696e48756e74722f0000000001603f352a010000001976a914c633315d376c20a973a758f7422d67f7bfed9c5888ac00000000", ["f0dbca1ee1a9f6388d07d97c1ab0de0e41acdf2edac4b95780ba0a1ec14103b3", "8e43fd2988ac40c5d97702b7e5ccdf5b06d58f0e0d323f74dd5082232c1aedf7", "1177601320ac928b8c145d771dae78a3901a089fa4aca8def01cbff747355818", "9f64f3b0d9edddb14be6f71c3ac2e80455916e207ffc003316c6a515452aa7b4", "2d0b54af60fad4ae59ec02031f661d026f2bb95e2eeb1e6657a35036c017c595"], "00000002", "1b148272", "52c7b81a", true], "id": null, "method": "mining.notify"}')
    logging.debug('TEST: %r' % reply)
    (job_id, prevhash, coinb1, coinb2, merkle_branches, version, nbits, ntime, clean_jobs) = reply['params']
    job = subscription.create_job(
        job_id=job_id,
        prevhash=prevhash,
        coinb1=coinb1,
        coinb2=coinb2,
        merkle_branches=merkle_branches,
        version=version,
        nbits=nbits,
        ntime=ntime
    )

    # Scan that job (if I broke something, this will run for a long time))
    for result in job.mine(nounce_start=1210450368 - 3):
        logging.debug('TEST: found share - %r' % repr(result))
        break

    valid = {'ntime': '52c7b81a', 'nounce': '482601c0', 'extranounce2': '00000000', 'job_id': u'1db7'}
    logging.debug('TEST: Correct answer %r' % valid)
