Testing
=======

Tests are available in the [tests](../tests) directory, and mostly consist of Python
scripts that compare generated code to [Capstone](http://www.capstone-engine.org) outputs.

[pytest](https://docs.pytest.org/en/latest/) was chosen as test runner,
since it is very easy to use, and shows nice recaps of failures using the
`assert` statement.

To run the tests, the [Python sources](../src/python)
must be built, which can be accomplished by running `make test`.
