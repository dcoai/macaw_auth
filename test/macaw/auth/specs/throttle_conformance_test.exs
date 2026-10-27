defmodule Macaw.Auth.Specs.ThrottleConformanceTest do
  @moduledoc """
  The model and the code agree (spec/10 §7). Behaviors are drawn from
  `Macaw.Auth.Specs.Throttle` at the code's own constants, two sign-ins in flight; each
  step is applied to the real table, and after every step the table must hold the
  model's rows, row for row, and `Throttle.check/3` must give the model's wait for every
  username and address.

  The mapping: `attempt` is a `check/3` that must give `:ok`; `succeed` is `success/1`;
  `fail` is `failure/3` with the time the attempt was admitted at; `sweep` is `sweep/1`,
  which must forget as many rows as the model's; `tick` moves the clock only. Model time
  `t` is `@t0 + t` ms.

  The same replay, with a defect §7 names in the code's place, must diverge: the check
  is shown to find what it is for.
  """
  use ExUnit.Case, async: false
  use ExUnitProperties

  alias ExTLA.ModelChecker
  alias ExTLA.Spec.Compiled
  alias Macaw.Auth.Native.Throttle
  alias Macaw.Auth.Specs.Throttle, as: Model

  # The code under check: the throttle, or a defect in its place.
  defmodule Shipped do
    def failure(user, address, now), do: Throttle.failure(user, address, now)
    def success(user, _address), do: Throttle.success(user)
  end

  # The throttle as it shipped before macaw_compose#67: the count, then the time.
  defmodule TwoStep do
    def failure(user, address, now) do
      for key <- [{:user, user} | if(address, do: [{:ip, address}], else: [])] do
        :ets.update_counter(Throttle, key, {2, 1}, {key, 0, now})
        :ets.update_element(Throttle, key, {3, now})
      end

      :ok
    end

    def success(user, _address), do: Throttle.success(user)
  end

  defmodule ForgetsAddress do
    def failure(user, address, now), do: Throttle.failure(user, address, now)

    def success(user, address) do
      Throttle.success(user)
      :ets.delete(Throttle, {:ip, address})
      :ok
    end
  end

  @t0 1_790_856_000_000
  @day 24 * 60 * 60 * 1000

  # The code's constants: five free failures, a second, 15 minutes, a day.
  @code %{
    free: 5,
    base: 1_000,
    cap: 15 * 60 * 1000,
    idle: @day,
    horizon: 100 * @day,
    ticks: MapSet.new([1, 999, 1_000, 30_000, 15 * 60 * 1000, @day]),
    max_failures: 40
  }

  @weights %{fail: 8, attempt: 4, tick: 2, succeed: 1, sweep: 1}

  @users %{u1: "u1", u2: "u2"}
  @addresses %{a1: "192.0.2.1", a2: "192.0.2.2", none: nil}

  setup do
    Throttle.reset()
    on_exit(&Throttle.reset/0)
  end

  @tag verifies: "throttle-model-conformance"
  property "many keys: two usernames, two addresses and none" do
    constants = constants(%{origins: MapSet.new([:a1, :a2, :none])})

    check all(steps <- behaviors(constants, 60), max_runs: 150) do
      assert replay(constants, steps, Shipped) == :ok
    end
  end

  # One username and one address, so a walk reaches the cap.
  @tag verifies: "throttle-model-conformance"
  property "one key pair, deep into the backoff" do
    constants = constants(%{users: MapSet.new([:u1]), origins: MapSet.new([:a1])})

    check all(steps <- behaviors(constants, 120), max_runs: 60) do
      assert replay(constants, steps, Shipped) == :ok
    end
  end

  # The check has teeth: each defect §7 names, put in the code's place, diverges
  # from the model on some drawn behavior.
  describe "the check finds the defects" do
    @tag verifies: "throttle-model-conformance"
    test "the shipped two-step failure: count, then write the failure's own time" do
      assert {:diverged, _step, _what} = first_divergence(TwoStep)
    end

    @tag verifies: "throttle-model-conformance"
    test "a success that forgets the address too" do
      assert {:diverged, {:succeed, _}, _what} = first_divergence(ForgetsAddress)
    end
  end

  # The first of a few hundred drawn behaviors on which `impl` diverges, at the
  # code's constants with one username and one address.
  defp first_divergence(impl) do
    constants = constants(%{users: MapSet.new([:u1]), origins: MapSet.new([:a1])})

    constants
    |> behaviors(60)
    |> Enum.take(300)
    |> Enum.find_value(fn steps ->
      case replay(constants, steps, impl) do
        :ok -> nil
        diverged -> diverged
      end
    end)
  end

  defp spec, do: Compiled.from_module(Model)

  defp constants(overrides),
    do: spec() |> Compiled.default_constants() |> Map.merge(@code) |> Map.merge(overrides)

  defp init(constants) do
    [init] = spec().init
    init.(constants)
  end

  # A behavior the model admits: each step enabled in the state the one before it
  # produced, as `ExTLA.PropertyTest.action_sequences/3` draws them, but weighted
  # toward failures, so that a walk reaches deep into the backoff rather than
  # resetting the username at every other step.
  defp behaviors(constants, max_length) do
    bind(integer(0..max_length), &walk(constants, init(constants), &1))
  end

  defp walk(_constants, _state, 0), do: constant([])

  defp walk(constants, state, remaining) do
    case ModelChecker.enabled_steps(spec(), constants, state) do
      [] ->
        constant([])

      steps ->
        steps
        |> Enum.map(fn {action, _} = step -> {Map.fetch!(@weights, action), constant(step)} end)
        |> frequency()
        |> bind(fn step ->
          constants
          |> walk(next(constants, state, step), remaining - 1)
          |> map(&[step | &1])
        end)
    end
  end

  defp next(constants, state, {action, params}),
    do: Compiled.action(spec(), action).transition.(constants, state, params)

  # `:ok` when the real table followed the model through every step, or the first
  # step after which it did not, and how.
  defp replay(constants, steps, impl) do
    Throttle.reset()

    steps
    |> Enum.reduce_while(init(constants), fn step, pre ->
      post = next(constants, pre, step)

      case apply_step(step, pre, post, impl) || disagreement(constants, post) do
        nil -> {:cont, post}
        what -> {:halt, {:diverged, step, what}}
      end
    end)
    |> case do
      {:diverged, _, _} = diverged -> diverged
      _state -> :ok
    end
  end

  # What the real table got wrong after a step, or nil.
  defp disagreement(constants, post) do
    rows = table()

    if rows == post.table do
      Enum.find_value(for(u <- constants.users, a <- constants.origins, do: {u, a}), fn {u, a} ->
        expected = expected_check(post, u, a, constants)
        actual = check(u, a, post.now)
        if actual != expected, do: {:check, u, a, actual, expected}
      end)
    else
      {:rows, rows, post.table}
    end
  end

  # Each step on the real table: nil, or what it got wrong at once.
  defp apply_step({:attempt, %{u: u, a: a}}, pre, _post, _impl) do
    case check(u, a, pre.now) do
      :ok -> nil
      refused -> {:attempt_refused, refused}
    end
  end

  defp apply_step({:succeed, %{p: p}}, pre, _post, impl) do
    {:verify, u, a, _ts} = pre.proc[p]
    impl.success(@users[u], @addresses[a])
    nil
  end

  defp apply_step({:fail, %{p: p}}, pre, _post, impl) do
    {:verify, u, a, ts} = pre.proc[p]
    impl.failure(@users[u], @addresses[a], @t0 + ts)
    nil
  end

  defp apply_step({:sweep, _}, pre, post, _impl) do
    forgot = Throttle.sweep(@t0 + pre.now)
    expected = MapSet.size(pre.table) - MapSet.size(post.table)
    if forgot != expected, do: {:sweep_forgot, forgot, expected}
  end

  defp apply_step({:tick, _}, _pre, _post, _impl), do: nil

  defp check(u, a, now), do: Throttle.check(@users[u], @addresses[a], @t0 + now)

  defp expected_check(state, u, a, c) do
    case Model.remaining(state.table, Model.attempt_keys(u, a), state.now, c.free, c.base, c.cap) do
      0 -> :ok
      ms -> {:delay, ms}
    end
  end

  # The real table, as the model's rows.
  defp table do
    Throttle
    |> :ets.tab2list()
    |> MapSet.new(fn {key, n, last} -> {model_key(key), n, last - @t0} end)
  end

  defp model_key({:user, name}), do: {:user, key_for(@users, name)}
  defp model_key({:ip, address}), do: {:ip, key_for(@addresses, address)}

  defp key_for(map, value), do: Enum.find_value(map, fn {k, v} -> v == value && k end)
end
