import assert from "node:assert/strict";
import { test } from "node:test";
import { runInNewContext } from "node:vm";
import { DECLARATIONS } from "./functions-fixture.mjs";
import { classifyCommand, verifyRuntime } from "../commands.mjs";

function fixture({ multiple = false, disabled = "" } = {}) {
  const events = [];
  const select = {
    multiple, disabled: disabled === "select", options: [],
    dispatchEvent(event) { events.push([event.type, event.bubbles]); },
    get selectedIndex() { return this.options.findIndex(option => option.selected); },
    get value() { return this.options.find(option => option.selected)?.value ?? ""; },
  };
  class HTMLOptionElement {
    constructor(value, selected) { this.value = value; this.selected = selected; this.disabled = disabled === "option"; }
    closest(tag) { return tag === "select" ? select : { disabled: disabled === "optgroup" }; }
  }
  class Event {
    constructor(type, options) { this.type = type; this.bubbles = options.bubbles; }
  }
  const first = new HTMLOptionElement("ios", multiple);
  const option = new HTMLOptionElement("mac", false);
  select.options = [first, option];
  const choose = runInNewContext(`(${DECLARATIONS.CHOOSE_OPTION})`, { HTMLOptionElement, Event });
  return { choose, option, first, select, events };
}

test("native option pin is input and reports the selected value after input then change", async () => {
  const command = { method: "Runtime.callFunctionOn", params: { objectId: "option", functionDeclaration: DECLARATIONS.CHOOSE_OPTION, returnByValue: true } };
  assert.equal(classifyCommand(command), "input");
  await verifyRuntime(command);
  const f = fixture();
  const result = f.choose.call(f.option);
  assert.equal(result.value, "mac");
  assert.equal(result.selectedIndex, 1);
  assert.deepEqual(f.events, [["input", true], ["change", true]]);
});

test("native multiple selection toggles only the addressed option", () => {
  const f = fixture({ multiple: true });
  f.choose.call(f.option);
  assert.equal(f.first.selected, true);
  assert.equal(f.option.selected, true);
  f.choose.call(f.option);
  assert.equal(f.first.selected, true);
  assert.equal(f.option.selected, false);
});

test("native option pin refuses non-options, orphan options and disabled controls", () => {
  const f = fixture();
  assert.throws(() => f.choose.call({}), /target is not an option/);
  f.option.closest = () => null;
  assert.throws(() => f.choose.call(f.option), /option has no select/);
  for (const disabled of ["option", "select", "optgroup"]) {
    const f = fixture({ disabled });
    assert.throws(() => f.choose.call(f.option), /is disabled/);
    assert.equal(f.option.selected, false);
    assert.deepEqual(f.events, []);
  }
});
