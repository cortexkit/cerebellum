//! Structured click geometry and projections used to determine whether a click
//! is intercepted.

use std::fmt;

use crate::coordinate::InputRect;

pub const SUBDIVISIONS: f64 = 64.0;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Quad {
    pub points: [(f64, f64); 4],
}
impl Quad {
    pub const fn new(points: [(f64, f64); 4]) -> Self {
        Self { points }
    }
    pub fn eligible(self) -> bool {
        if self
            .points
            .iter()
            .any(|(x, y)| !x.is_finite() || !y.is_finite())
        {
            return false;
        }
        let mut area = 0.0;
        for index in 0..4 {
            let next = (index + 1) % 4;
            area += self.points[index].0 * self.points[next].1
                - self.points[next].0 * self.points[index].1;
        }
        area.abs() > 0.0
    }
    pub fn midpoint(self) -> Result<(f64, f64), GeometryError> {
        if !self.eligible() {
            return Err(GeometryError::NoEligibleQuad);
        }
        let min_x = self
            .points
            .iter()
            .map(|point| point.0)
            .fold(f64::INFINITY, f64::min);
        let max_x = self
            .points
            .iter()
            .map(|point| point.0)
            .fold(f64::NEG_INFINITY, f64::max);
        let min_y = self
            .points
            .iter()
            .map(|point| point.1)
            .fold(f64::INFINITY, f64::min);
        let max_y = self
            .points
            .iter()
            .map(|point| point.1)
            .fold(f64::NEG_INFINITY, f64::max);
        round_css((min_x + max_x) / 2.0)
            .and_then(|x| round_css((min_y + max_y) / 2.0).map(|y| (x, y)))
    }
    pub fn bit_patterns(self) -> [u64; 8] {
        [
            self.points[0].0.to_bits(),
            self.points[0].1.to_bits(),
            self.points[1].0.to_bits(),
            self.points[1].1.to_bits(),
            self.points[2].0.to_bits(),
            self.points[2].1.to_bits(),
            self.points[3].0.to_bits(),
            self.points[3].1.to_bits(),
        ]
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct GeometryProjection {
    pub response_index: usize,
    pub quad_bits: [u64; 8],
    pub x_bits: u64,
    pub y_bits: u64,
    pub x_css: f64,
    pub y_css: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeometryError {
    NoEligibleQuad,
    NonFinite,
    OutsideViewport,
}
impl fmt::Display for GeometryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for GeometryError {}

pub fn select_first_eligible(quads: &[Quad]) -> Result<GeometryProjection, GeometryError> {
    let (index, quad) = quads
        .iter()
        .copied()
        .enumerate()
        .find(|(_, quad)| quad.eligible())
        .ok_or(GeometryError::NoEligibleQuad)?;
    let (x_css, y_css) = quad.midpoint()?;
    Ok(GeometryProjection {
        response_index: index,
        quad_bits: quad.bit_patterns(),
        x_bits: x_css.to_bits(),
        y_bits: y_css.to_bits(),
        x_css,
        y_css,
    })
}

pub fn require_point_in_viewport(
    x_css: f64,
    y_css: f64,
    viewport: InputRect,
) -> Result<(), GeometryError> {
    let right = viewport.x_input_css + viewport.width_input_css;
    let bottom = viewport.y_input_css + viewport.height_input_css;
    if ![
        x_css,
        y_css,
        viewport.x_input_css,
        viewport.y_input_css,
        viewport.width_input_css,
        viewport.height_input_css,
        right,
        bottom,
    ]
    .into_iter()
    .all(f64::is_finite)
    {
        return Err(GeometryError::NonFinite);
    }
    if viewport.width_input_css <= 0.0 || viewport.height_input_css <= 0.0 {
        return Err(GeometryError::NonFinite);
    }
    if x_css < viewport.x_input_css
        || x_css >= right
        || y_css < viewport.y_input_css
        || y_css >= bottom
    {
        return Err(GeometryError::OutsideViewport);
    }
    Ok(())
}

pub fn round_css(value: f64) -> Result<f64, GeometryError> {
    if !value.is_finite() {
        return Err(GeometryError::NonFinite);
    }
    let scaled = value * SUBDIVISIONS;
    if !scaled.is_finite() {
        return Err(GeometryError::NonFinite);
    }
    // floor(v + 0.5) gives the specified positive-infinity tie rule for both
    // positive and negative CSS coordinates.
    let rounded = (scaled + 0.5).floor() / SUBDIVISIONS;
    rounded
        .is_finite()
        .then_some(rounded)
        .ok_or(GeometryError::NonFinite)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HitProjection {
    pub target_id: String,
    pub frame_id: String,
    pub point_x_bits: u64,
    pub point_y_bits: u64,
    pub topmost_identity: String,
    pub accepted: bool,
}

pub fn accept_hit(
    target_identity: &str,
    descendant_identities: &[&str],
    topmost_identity: &str,
) -> bool {
    topmost_identity == target_identity || descendant_identities.contains(&topmost_identity)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_eligible_quad_and_midpoint_are_stable() {
        let quads = [
            Quad::new([(0.0, 0.0); 4]),
            Quad::new([(0.0, 0.0), (10.0, 0.0), (10.0, 4.0), (0.0, 4.0)]),
        ];
        let projection = select_first_eligible(&quads).unwrap();
        assert_eq!(projection.response_index, 1);
        assert_eq!((projection.x_css, projection.y_css), (5.0, 2.0));
    }

    #[test]
    fn exact_half_rounds_toward_positive_infinity() {
        assert_eq!(round_css(0.5 / SUBDIVISIONS).unwrap(), 1.0 / SUBDIVISIONS);
        assert_eq!(round_css(-0.5 / SUBDIVISIONS).unwrap(), 0.0);
    }
}
