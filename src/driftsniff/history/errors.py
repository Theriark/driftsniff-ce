"""What the history and configuration services refuse."""


class StoredConfigurationError(Exception):
    """A stored manifest or state is missing, damaged or does not match its address.

    The text is fixed and never quotes stored data; the cause is chained for the log.
    """
