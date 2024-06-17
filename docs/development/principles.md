# Project Principles

## Pre-run -> Run -> Post-run

In the root command, we set a `PersistentPreRunE` and `PersistentPostRunE` function that is responsible for initializing the output format and Signal data (in the pre-run) and then write that data in the proper format (in the post-run).

Within the Run command that every command must implement, the output of the collected data needs to be written back to the struct's `OutputSignal.Content` value in order to be properly written out to the caller.

## Cmd vs Internal

By design, the functionality within each command should focus around parsing the variety of flags and options that the command may need to control capability, passing off all real logic into internal modules.
