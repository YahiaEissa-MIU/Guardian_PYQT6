# stubs.py
"""Temporary stub classes for testing during development"""


class BaseStub:
    """Base stub that logs method calls for debugging"""

    def __getattr__(self, name):
        def method(*args, **kwargs):
            print(f"STUB CALL: {self.__class__.__name__}.{name}({args}, {kwargs})")
            return None

        return method


# Views


class AboutSystemView(BaseStub): pass




