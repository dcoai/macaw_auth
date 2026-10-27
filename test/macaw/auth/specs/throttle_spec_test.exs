defmodule Macaw.Auth.Specs.ThrottleTest do
  @moduledoc """
  `Macaw.Auth.Specs.Throttle` (spec/10 §7): the design verifies over every interleaving,
  and each defect is FOUND by the checker when its switch is flipped. A model that could
  not see them would prove nothing about the design.
  """
  use ExUnit.Case, async: true

  import ExTLA.Spec.Test
  import ExUnit.CaptureIO

  alias Macaw.Auth.Specs.Throttle

  # The scaled instance `mix auth.verify` checks: the constants' defaults.
  defp run(overrides, invariants) do
    ExTLA.ModelChecker.run(Throttle, %{constants: overrides, invariants: invariants})
  end

  # Coverage warns that `stamp` and `write` are never enabled: they are the defects'
  # second steps. The warning is asserted rather than printed.
  @tag verifies: "throttle-model"
  test "the design: every invariant, over every interleaving" do
    assert capture_io(:stderr, fn -> assert_spec(Throttle, %{}) end) =~
             "action :stamp was never enabled"
  end

  @tag verifies: "throttle-model"
  test "the design with a caller that has no address" do
    assert capture_io(:stderr, fn ->
             assert_spec(Throttle, %{constants: %{origins: MapSet.new([:none])}})
           end) =~ "action :write was never enabled"
  end

  describe "the defects, found by the checker" do
    # The code as it shipped: `update_counter`, then `update_element` with the
    # failure's own time. A check between the two reads the new count from the old
    # time, and a later attempt is admitted inside its wait.
    @tag verifies: "throttle-model-defects"
    test "counting, then stamping: an attempt is admitted early" do
      result = run(%{atomic_stamp: false}, [:no_early_admit])

      assert result.status == :violation
      trace = ExTLA.Trace.format(result.violation)
      assert trace =~ "no_early_admit"
      assert trace =~ ~r/early_admit\s+= true   ← changed/
    end

    # The same defect, at rest: the earlier failure's stamp lands second, and the
    # row keeps its time, not the latest.
    @tag verifies: "throttle-model-defects"
    test "counting, then stamping: the row keeps an earlier failure's time" do
      result = run(%{atomic_stamp: false}, [:last_is_latest])

      assert result.status == :violation
      trace = ExTLA.Trace.format(result.violation)
      assert trace =~ "stamp(p: :p2)"
      assert trace =~ ~r/stamp\(p: :p1\).*\[VIOLATION\]/s
    end

    @tag verifies: "throttle-model-defects"
    test "a lookup, then an insert: concurrent failures count once" do
      result = run(%{atomic_increment: false}, [:failures_each_count])

      assert result.status == :violation
      assert ExTLA.Trace.format(result.violation) =~ "failures_each_count"
    end

    @tag verifies: "throttle-model-defects"
    test "a success that resets the address too" do
      result = run(%{success_resets_address: true}, :all)

      assert result.status == :violation
      trace = ExTLA.Trace.format(result.violation)
      assert trace =~ "success_keeps_address"
      assert trace =~ ~r/address_lowered\s+= true   ← changed/
    end

    @tag verifies: "throttle-model-defects"
    test "a success that resets the address too: a guesser is admitted early" do
      result = run(%{success_resets_address: true}, [:no_early_admit])

      assert result.status == :violation
      assert ExTLA.Trace.format(result.violation) =~ "succeed(p:"
    end
  end
end
