# pylint: disable=unused-argument,multiple-statements,super-init-not-called
from typing import Any

from botocore.hooks import BaseEventHooks

def inject_delete_tags(event_emitter: BaseEventHooks, **kwargs: Any) -> None: ...
def delete_tags(self: Any, **kwargs: Any) -> None: ...
