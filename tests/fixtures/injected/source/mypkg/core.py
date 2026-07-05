# core module of the fixture package
# (comments and formatting here differ from the wheel copy on purpose:
#  the AST normalizer must treat both as identical)


def greet(name: str) -> str:
    # build the greeting
    message = "hello, " + name
    return message


def add(a: int, b: int) -> int:
    return a + b
