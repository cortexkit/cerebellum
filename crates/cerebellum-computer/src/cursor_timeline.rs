//! When the agent badge's pointer tip reaches the place it was sent to.
//!
//! Two programs need the same answer. The helper process animates the badge:
//! a first appearance plays an entry on the target, and every later action
//! glides there. The module holds each action until that moment, so the real
//! click lands together with the badge's tap rather than ahead of it.
//!
//! This one file is compiled into both crates: `cerebellum-computer` declares
//! it as a module, and `cerebellum-macos` (the helper's crate, which cannot
//! depend on `cerebellum-computer`) includes it by path. A change to any
//! timing here changes both sides at once, so they cannot drift apart. Keep
//! it free of `use crate::...`, so it compiles the same in either crate.

/// How long a first appearance takes, in ms: the avatar pops in large on the
/// target, holds a moment, then shrinks onto its place behind the pointer as
/// the pointer and label come in. The original entry felt too quick, so each
/// phase now takes twice as long while the gentler Reduce Motion fade stays
/// short.
pub const ENTRY_MS: f64 = 1040.0;

/// Under Reduce Motion an entry is a plain fade of the resting badge, with no
/// scaling and no travel, over this many ms.
pub const REDUCED_ENTRY_MS: f64 = 300.0;

/// The quickest glide, in ms, for any move of half a point or more.
const SHORTEST_GLIDE_MS: f64 = 180.0;

/// How much longer a glide takes for each point of distance, in ms.
const GLIDE_MS_PER_POINT: f64 = 0.25;

/// The longest glide, in ms: a move across the whole screen.
pub const LONGEST_GLIDE_MS: f64 = 450.0;

/// Under Reduce Motion a move is a short fade instead of a glide, whatever
/// the distance.
pub const REDUCED_MOVE_MS: f64 = 140.0;

/// How long a resting badge stays fully visible after its agent's last
/// event, in ms, before it starts to fade out. Agents pause between actions
/// for minutes at a time, so two minutes outlasts an ordinary pause; the
/// normal way a badge leaves is an explicit end, and this is only the safety
/// net for an end that never arrives.
pub const IDLE_FADE_AFTER_MS: u64 = 2 * 60 * 1000;

/// How long that idle fade takes, in ms. Once it is over the badge is gone,
/// and the agent's next action is a new first appearance with an entry.
pub const IDLE_FADE_MS: u64 = 250;

/// The longest any badge takes to reach its target, in ms: the entry or the
/// longest glide, whichever is longer.
pub const LONGEST_ARRIVAL_MS: f64 = if ENTRY_MS > LONGEST_GLIDE_MS {
    ENTRY_MS
} else {
    LONGEST_GLIDE_MS
};

/// How long a first appearance's entry takes, in ms.
pub fn entry_ms(reduce_motion: bool) -> f64 {
    if reduce_motion {
        REDUCED_ENTRY_MS
    } else {
        ENTRY_MS
    }
}

/// Glide time grows with distance, from a quick 180 ms hop to a 450 ms
/// cross-screen move, so short moves feel snappy and long ones stay legible.
/// With Reduce Motion the picture does a short fade-move instead of gliding.
/// A zero or malformed distance needs no glide at all.
pub fn duration_ms(distance: f64, reduce_motion: bool) -> f64 {
    let distance = if distance.is_finite() {
        distance.max(0.0)
    } else {
        0.0
    };
    if distance < 0.5 {
        return 0.0;
    }
    if reduce_motion {
        return REDUCED_MOVE_MS;
    }
    (SHORTEST_GLIDE_MS + distance * GLIDE_MS_PER_POINT).min(LONGEST_GLIDE_MS)
}

/// How long after a picture event the badge's tip is on its target, in ms.
///
/// A first appearance does not travel: the badge starts on the target and
/// plays its entry there, so it has arrived when the entry ends. Every later
/// event glides from where the tip was last drawn, `distance` points away.
pub fn tip_arrival_ms(distance: f64, first: bool, reduce_motion: bool) -> f64 {
    if first {
        entry_ms(reduce_motion)
    } else {
        duration_ms(distance, reduce_motion)
    }
}
