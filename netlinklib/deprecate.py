from functools import partial, wraps
from typing import Any, Callable
from warnings import warn


def deprecated(fun: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(fun)
    def _fun(*args: Any, **kwargs: Any) -> Any:
        warn(
            f"{fun.func.__name__ if isinstance(fun, partial) else fun.__name__}"
            " is deprecated.",
            DeprecationWarning,
            stacklevel=2,
        )
        return fun(*args, **kwargs)

    return _fun
