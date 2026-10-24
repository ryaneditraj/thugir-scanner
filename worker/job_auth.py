"""QStash signature check for Deep Scan jobs.

Unsigned jobs are accepted only when ALLOW_UNSIGNED_JOBS=1, which is a local
development switch and must not be set on a deployed worker.
"""

from __future__ import annotations

import os


def verify_qstash(body: bytes, signature: str | None) -> bool:
    if signature:
        try:
            from qstash import Receiver

            receiver = Receiver(
                current_signing_key=os.environ["QSTASH_CURRENT_SIGNING_KEY"],
                next_signing_key=os.environ["QSTASH_NEXT_SIGNING_KEY"],
            )
            receiver.verify(signature=signature, body=body.decode("utf-8"))
            return True
        except Exception:
            return False
    return os.getenv("ALLOW_UNSIGNED_JOBS") == "1"
