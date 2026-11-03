Policy
------

- The `-rejectbpub` option is removed. 1-of-N multisig inputs whose keys carry known spam are now always counted as non-standard data carrier bytes. Passing `-rejectbpub` on the command line now fails at startup.
