"""Exceptions raised for problems the user can fix (bad config, unknown IDs, missing files)."""


class LagError(Exception):
    """A user-facing error. The CLI prints the message without a traceback."""
