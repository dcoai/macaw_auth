defmodule Macaw.Auth.Specs.Throttle do
  @moduledoc """
  `Macaw.Auth.Native.Throttle` as a model (spec/10 §7): the table of failures, shared by
  every sign-in in flight, and what each call does to it.

  **State.** `table` is the `macaw_auth_throttle` table, row for row: a set of
  `{key, failures, last}`, where a key is `{:user, u}` (`u` an account, or a name no
  account has: the throttle counts both alike) or `{:ip, a}` and `last` is the
  last-failure time. `now` is
  the clock. `proc` is each sign-in in flight: `:idle`, or admitted at `ts` and verifying
  its password, or part-way through recording its failure. Two history variables record
  a broken rule once it has happened: `early_admit` and `address_lowered`. `truth` is a
  ghost, the table as the throttle's rules define it: for each key, the failures counted
  since its last reset, and the latest of their times. The invariants hold the table to it.

  **Actions.** `attempt(p, u, a)`: `Throttle.check/3` at `now` admits a sign-in from
  address `a` (`:none` is a caller with no address); the model has no refused attempt,
  since a refusal changes nothing. `succeed(p)`: `Throttle.success/1`. `fail(p)`:
  `Throttle.failure/3` with the time the sign-in was admitted at, which may be older than
  `now` and older than another sign-in's failure. `tick(d)`: time passes. `sweep`:
  `Throttle.sweep/1` at `now`. `restart`: the node restarts (a crash, a deploy): every
  sign-in in flight dies, and the table, in the database, stays.

  **What is abstracted.** A failure upserts its keys in one statement, which the
  database applies row by row; the model updates them in one step. Every operation
  reads and writes one key alone (a sweep
  decides each key on its own row), so the order across keys changes nothing a key's
  own history shows. Within a key, the steps are kept as the code takes them. A check
  reads its keys in one step. A check and the failure that follows it are separate
  steps, as in the code: concurrent sign-ins can all be admitted before any of their
  failures is counted.

  **Time** is a bounded integer (`horizon`), advanced by `ticks`. The constants are the
  code's (five free failures, a second, 15 minutes, a day) when the model is run against
  the code, and a scaled instance (one free failure, waits of 1 and 2, a sweep after 3)
  when it is checked exhaustively: the rules are the same, and the scaled waits keep the
  state space small. `max_failures` bounds the failures counted on a key: an attempt
  starts only on keys below it.

  Three constants select the design (the default) or a defect, and the tests in
  `test/macaw/auth/specs/` prove the checker finds each:

    * `atomic_stamp` - a failure counts and stamps its key in one atomic step, keeping
      the later of the row's time and its own. `false` is the code as it shipped: an
      `update_counter`, then an `update_element` that writes its own time.
    * `atomic_increment` - the count is an atomic increment. `false` is a lookup, then
      an insert, as a naive table would do.
    * `success_resets_address` - `false`: a success forgets the username's count only.
      `true` forgets the address's too.
    * `persistent` - the table survives a restart. `false` is the table in memory, as it
      shipped before macaw_auth#4: a restart empties it.
  """

  use ExTLA.Spec

  constant(:users, default: set([:u1, :u2]))
  constant(:origins, default: set([:a1]))
  constant(:procs, default: set([:p1, :p2]))
  constant(:free, default: 1)
  constant(:base, default: 1)
  constant(:cap, default: 2)
  constant(:idle, default: 3)
  constant(:horizon, default: 4)
  constant(:ticks, default: set([1]))
  constant(:max_failures, default: 3)
  constant(:atomic_stamp, default: true)
  constant(:atomic_increment, default: true)
  constant(:success_resets_address, default: false)
  constant(:persistent, default: true)

  variable(:now, type: 0..^horizon)
  variable(:table, type: set({{:user, ^users} | {:ip, ^origins}, :nat, 0..^horizon}))
  variable(:truth, type: set({{:user, ^users} | {:ip, ^origins}, :nat, 0..^horizon}))

  variable(:proc,
    type: [
      ^procs
      ~> (:idle
          | {:verify, ^users, ^origins, 0..^horizon}
          | {:stamp, ^users, ^origins, 0..^horizon}
          | {:write, ^users, ^origins, 0..^horizon, seq(:nat)})
    ]
  )

  variable(:early_admit, type: [true, false])
  variable(:address_lowered, type: [true, false])

  init do
    now = 0
    table = set()
    truth = set()
    proc = for_each(^procs, fn _ -> :idle end)
    early_admit = false
    address_lowered = false
  end

  # `Throttle.check/3` at `now` gives `:ok`: neither key waits, by the table. Whether
  # the rules agree is what `early_admit` records.
  action :attempt, params: [p: ^procs, u: ^users, a: ^origins] do
    require proc[p] == :idle
    require below?(truth, attempt_keys(u, a), ^max_failures)
    require remaining(table, attempt_keys(u, a), now, ^free, ^base, ^cap) == 0
    proc = update(proc, p, fn _ -> {:verify, u, a, now} end)

    early_admit =
      early_admit or remaining(truth, attempt_keys(u, a), now, ^free, ^base, ^cap) > 0
  end

  # The password was right: `Throttle.success/1`.
  action :succeed, params: [p: ^procs] do
    require phase(proc[p]) == :verify
    let({:verify, u, a, _ts} = proc[p])
    let(after_success = succeed_rows(table, u, a, ^success_resets_address))
    table = after_success
    truth = drop(truth, {:user, u})
    proc = update(proc, p, fn _ -> :idle end)
    address_lowered = address_lowered or lowers_address?(table, after_success)
  end

  # The password was wrong: `Throttle.failure/3`, with the time the attempt was
  # admitted at. Its keys are counted now in the design, and once the stamp or the
  # write follows in the defects.
  action :fail, params: [p: ^procs] do
    require phase(proc[p]) == :verify
    let({:verify, u, a, ts} = proc[p])
    let(keys = attempt_keys(u, a))

    table =
      cond do
        not (^atomic_increment) -> table
        ^atomic_stamp -> record_all(table, keys, ts)
        true -> count_all(table, keys, ts)
      end

    truth = if ^atomic_increment, do: record_all(truth, keys, ts), else: truth

    proc =
      update(proc, p, fn _ ->
        cond do
          not (^atomic_increment) -> {:write, u, a, ts, Enum.map(keys, &count(table, &1))}
          ^atomic_stamp -> :idle
          true -> {:stamp, u, a, ts}
        end
      end)
  end

  # The shipped failure's second step: `update_element` writes the attempt's own time
  # into each row that still exists.
  action :stamp, params: [p: ^procs] do
    require phase(proc[p]) == :stamp
    let({:stamp, u, a, ts} = proc[p])
    table = stamp_all(table, attempt_keys(u, a), ts)
    proc = update(proc, p, fn _ -> :idle end)
  end

  # A naive failure's second step: the insert of what the lookup read, plus one.
  action :write, params: [p: ^procs] do
    require phase(proc[p]) == :write
    let({:write, u, a, ts, read} = proc[p])
    table = write_all(table, attempt_keys(u, a), read, ts)
    truth = record_all(truth, attempt_keys(u, a), ts)
    proc = update(proc, p, fn _ -> :idle end)
  end

  action :tick, params: [d: ^ticks] do
    require now + d <= ^horizon
    now = now + d
  end

  # The node restarts: the sign-ins in flight die before they are counted, which is
  # no reset (`truth` keeps every failure counted). The table stays, in the database;
  # held in memory, it is lost. Not between a defect's two steps: the design has no
  # such step, and the defects are found without it.
  action :restart do
    require Enum.all?(^procs, fn p -> phase(proc[p]) in [:idle, :verify] end)
    proc = for_each(^procs, fn _ -> :idle end)
    table = if ^persistent, do: table, else: set()
  end

  # `Throttle.sweep/1` at `now`: a key whose last failure is more than `idle` old.
  action :sweep do
    table = sweep_rows(table, now - ^idle)
    truth = sweep_rows(truth, now - ^idle)
  end

  invariant :no_early_admit,
    desc: "an attempt is admitted only once each key's wait has passed since its last failure" do
    not early_admit
  end

  invariant :success_keeps_address, desc: "a success never lowers an address's count" do
    not address_lowered
  end

  invariant :failures_each_count,
    desc: "a key at rest counts every failure since its last reset" do
    Enum.all?(settled_keys(table, truth, proc), fn k -> count(table, k) == count(truth, k) end)
  end

  invariant :last_is_latest, desc: "a key at rest holds the latest of its failures' times" do
    Enum.all?(settled_keys(table, truth, proc), fn k -> last(table, k) == last(truth, k) end)
  end

  invariant :wait_capped, desc: "no key waits longer than the cap" do
    Enum.all?(table, fn {k, _, _} -> remaining(table, [k], now, ^free, ^base, ^cap) <= ^cap end)
  end

  # The keys an attempt counts: no address, no address key.
  def attempt_keys(u, :none), do: [{:user, u}]
  def attempt_keys(u, a), do: [{:user, u}, {:ip, a}]

  # `Throttle.delay_ms/1`, over the model's constants.
  def delay(n, free, _base, _cap) when n < free, do: 0
  def delay(n, free, base, cap), do: min(Integer.pow(2, n - free) * base, cap)

  # `Throttle.check/3`: the longer of the keys' waits left at `now`.
  def remaining(rows, keys, now, free, base, cap) do
    keys
    |> Enum.map(fn key ->
      case row(rows, key) do
        nil -> 0
        {_, n, last} -> max(delay(n, free, base, cap) - (now - last), 0)
      end
    end)
    |> Enum.max()
  end

  def below?(rows, keys, max), do: Enum.all?(keys, &(count(rows, &1) < max))

  def phase(:idle), do: :idle
  def phase(in_flight), do: elem(in_flight, 0)

  def row(rows, key), do: Enum.find(rows, &(elem(&1, 0) == key))

  def count(rows, key) do
    case row(rows, key) do
      nil -> 0
      {_, n, _} -> n
    end
  end

  def last(rows, key) do
    case row(rows, key) do
      nil -> nil
      {_, _, last} -> last
    end
  end

  def drop(rows, key), do: MapSet.reject(rows, &(elem(&1, 0) == key))

  defp replace(rows, key, new_row), do: rows |> drop(key) |> MapSet.put(new_row)

  # One failure, atomically: one more, and the later of the two times.
  def record_all(rows, keys, ts) do
    Enum.reduce(keys, rows, fn key, acc ->
      case row(acc, key) do
        nil -> MapSet.put(acc, {key, 1, ts})
        {_, n, last} -> replace(acc, key, {key, n + 1, max(last, ts)})
      end
    end)
  end

  # `update_counter` with a default row: one more, the time left as it was.
  def count_all(rows, keys, ts) do
    Enum.reduce(keys, rows, fn key, acc ->
      case row(acc, key) do
        nil -> MapSet.put(acc, {key, 1, ts})
        {_, n, last} -> replace(acc, key, {key, n + 1, last})
      end
    end)
  end

  # `update_element`: the attempt's own time, on a row that still exists.
  def stamp_all(rows, keys, ts) do
    Enum.reduce(keys, rows, fn key, acc ->
      case row(acc, key) do
        nil -> acc
        {_, n, _} -> replace(acc, key, {key, n, ts})
      end
    end)
  end

  def write_all(rows, keys, read, ts) do
    keys
    |> Enum.zip(read)
    |> Enum.reduce(rows, fn {key, n}, acc -> replace(acc, key, {key, n + 1, ts}) end)
  end

  def succeed_rows(rows, u, a, resets_address) do
    rows = drop(rows, {:user, u})
    if resets_address and a != :none, do: drop(rows, {:ip, a}), else: rows
  end

  def lowers_address?(before, after_success) do
    Enum.any?(before, fn
      {{:ip, _} = key, n, _} -> count(after_success, key) < n
      _ -> false
    end)
  end

  def sweep_rows(rows, cutoff), do: MapSet.reject(rows, fn {_, _, last} -> last < cutoff end)

  # Keys no failure is part-way through.
  def settled_keys(table, truth, proc) do
    busy =
      for {_, flight} <- proc,
          phase(flight) in [:stamp, :write],
          key <- attempt_keys(elem(flight, 1), elem(flight, 2)),
          do: key

    (Enum.map(table, &elem(&1, 0)) ++ Enum.map(truth, &elem(&1, 0)))
    |> Enum.uniq()
    |> Enum.reject(&(&1 in busy))
  end
end
