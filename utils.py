import functools

class Memoized(object):
    """Decorator that caches a function's return value each time it is called.
    If called later with the same arguments, the cached value is returned, and
    not re-evaluated.
    """

    cache = {}

    def __init__(self, func):
        self.func = func
        self.key = (func.__module__, func.__name__)
        self.cache[self.key] = {}

    def __call__(self, *args):
      try:
          return Memoized.cache[self.key][args]
      except KeyError:
          value = self.func(*args)
          Memoized.cache[self.key][args] = value
          return value
      except TypeError:
          # uncachable -- for instance, passing a list as an argument.
          # Better to not cache than to blow up entirely.
          return self.func(*args)

    def __get__(self, obj, objtype):
        """Support instance methods."""
        return functools.partial(self.__call__, obj)

    @staticmethod
    def reset():
        Memoized.cache = {}
