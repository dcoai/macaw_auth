# Depdep: restore compiled dependencies from the DCOTek group's shared store
# before `mix deps.get`, and push what was missing after a green build.
#
#   elixir scripts/depdep.exs --pull --mix-get --compile-deps   # the pull, mix deps.get
#                                                              # inside it, and a compile of
#                                                              # what the store lacked
#   elixir scripts/depdep.exs --push                           # after the build succeeded
#
# Set up as visualize's is (macaw_compose spec/00 §4.1, #66): depdep comes from Hex, the
# range floats over patch releases only (a minor moves the key schema, and crossing one
# should be a decision), and the store is named by the group's DEPDEP_* variables, never
# by this project or this file. Without them depdep says so and exits 0, and a store that
# can't be reached degrades to a cold build, never a failed one. depdep is this project's
# only dependency cache: no job has a runner `cache:`, so each job's summary (`pulled`,
# `missing`, `rebuilt N`) measures depdep itself. A non-zero `rebuilt` is explained by
# `--explain-rebuilt`.
Mix.install([{:depdep, "~> 0.12.0"}])

Depdep.CLI.main(System.argv())
