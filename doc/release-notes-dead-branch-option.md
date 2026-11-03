Policy
------

- The `-rejectdeadbranches` option is removed. Data in a conditional part that constants make unreachable is now always counted as data carrier bytes, as the `OP_FALSE OP_IF` envelope already was, and `-corepolicy` no longer turns that counting off. Passing `-rejectdeadbranches` on the command line now fails at startup.
