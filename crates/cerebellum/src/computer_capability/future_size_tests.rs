//! Measure the native computer futures without polling platform operations.

use super::*;

pub(crate) fn sizes<C: MonotonicClock>(
    plane: &RunningComputerPlane,
    arguments: &Value,
    context: ServeContext<'_, C>,
) -> Vec<(&'static str, usize)> {
    vec![
        (
            "ComputerPlane::serve",
            std::mem::size_of_val(&plane.serve(
                servable("computer.wait").unwrap(),
                arguments,
                context.clone(),
                |_| native_capture_backend(),
            )),
        ),
        (
            "ComputerPlane::serve_wait",
            std::mem::size_of_val(&plane.serve_wait(arguments, context.clone())),
        ),
        (
            "ComputerPlane::serve_read_state",
            std::mem::size_of_val(
                &plane.serve_read_state(arguments, context.clone(), |_| native_capture_backend()),
            ),
        ),
        (
            "ComputerPlane::serve_synthetic",
            std::mem::size_of_val(&plane.serve_synthetic(
                ComputerCapability::Type,
                arguments,
                context.clone(),
            )),
        ),
        (
            "ComputerPlane::serve_press_element",
            std::mem::size_of_val(&plane.serve_press_element(arguments, context.clone())),
        ),
        (
            "ComputerPlane::serve_press_point",
            std::mem::size_of_val(&plane.serve_press_point(arguments, context.clone())),
        ),
        (
            "ComputerPlane::serve_write_text",
            std::mem::size_of_val(&plane.serve_write_text(arguments, context.clone())),
        ),
        (
            "ComputerPlane::serve_open_app",
            std::mem::size_of_val(&plane.serve_open_app(arguments, context.clone())),
        ),
        (
            "ComputerPlane::serve_takeover",
            std::mem::size_of_val(&plane.serve_takeover(
                ComputerCapability::TakeoverMove,
                arguments,
                context,
            )),
        ),
    ]
}
