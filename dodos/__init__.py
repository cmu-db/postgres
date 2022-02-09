import inspect
from pathlib import Path

# doit verbosity default controls what to print.
# 0 = nothing, 1 = stderr only, 2 = stdout and stderr.
VERBOSITY_DEFAULT = 2


def default_artifacts_path():
    """
    Compute the path to be used for artifacts.

    The returned folder is for output artifacts that external users would care about.
    This can include binaries and CSV files.

    Returns
    -------
    artifacts_path : Path | str
        Path for storing artifacts in.
    """

    caller_stack = inspect.stack()[1]
    module_name = Path(caller_stack.filename).stem
    return (Path("artifacts") / module_name).absolute()


def default_build_path():
    """
    Compute the path to be used for build.

    This is a folder for internal stuff that external users would not care about.
    The component can do whatever you want in here.

    Returns
    -------
    build_path : Path | str
        Path for storing build components in.
    """

    caller_stack = inspect.stack()[1]
    module_name = Path(caller_stack.filename).stem
    return (Path("build") / module_name).absolute()
