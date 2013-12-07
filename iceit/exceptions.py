class IceItException(Exception):
    """
    Base exception class
    """
    pass

class UnexpectedResultException(IceItException):
    """
    Raised when receiving an unexpected result
    """
    pass