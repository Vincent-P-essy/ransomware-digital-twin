"""Domain failures surfaced consistently by CLI and API."""


class DigitalTwinError(Exception):
    """Base class for controlled failures."""


class ValidationError(DigitalTwinError):
    """A strict input contract was not satisfied."""


class IntegrityError(DigitalTwinError):
    """Pinned data or a hash chain failed verification."""
