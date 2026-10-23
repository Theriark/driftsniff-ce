"""What the change services refuse, as exceptions the routes turn into answers."""


class ChangeActionError(Exception):
    """Base of every refusal; nothing was stored when one is raised."""


class ActionForbiddenError(ChangeActionError):
    """The signed-in role may not do this (acknowledging, notes and mutes need operator)."""


class UnknownChangeError(ChangeActionError):
    """No change event has this id."""


class UnknownItemError(ChangeActionError):
    """No change item has this id."""


class UnknownMuteError(ChangeActionError):
    """No mute has this id."""


class InvalidTextError(ChangeActionError):
    """A comment, note or reason is empty, too long or holds characters that cannot be stored."""


class EntryLimitError(ChangeActionError):
    """The change already holds the most acknowledgements or notes it may hold."""


class NotMutableError(ChangeActionError):
    """The item cannot be muted: it is critical, or its path is not a path a mute can match."""
