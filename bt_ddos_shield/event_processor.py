from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class Event:
    """
    Class describing event, which happened in the shield.
    """

    event_description: str       # Description of the event.
    exception: Exception = None  # Exception which caused the event.


class AbstractEventProcessor(ABC):
    """
    Abstract base class for processor handling events generated by shield.
    """

    @abstractmethod
    def add_event(self, event: Event):
        """
        Add new event to be handled by processor.

        Args:
            event: Event to add.
        """
        pass
