//! Linear scaling transformations between domain and range
//!
//! Used for mapping data coordinates to screen coordinates and vice versa.
//!
//! ## Example
//! ```rust
//! let scale = Scale::new(0.0..100.0, 0.0..800.0);
//!
//! // Map from data domain to screen range
//! assert_eq!(scale.linear(50.0), 400.0); // 50% → 400 pixels
//!
//! // Map from screen range back to data domain
//! assert_eq!(scale.inv_linear(400.0), 50.0); // 400 pixels → 50%
//! ```

use std::ops::Range;

/// Maps values between domain (data space) and range (screen space)
pub struct Scale {
    domain: Range<f32>,
    range: Range<f32>,
}

impl Scale {
    /// Create a new scale mapping from domain to range
    ///
    /// # Arguments
    /// * `domain` - Input value range (e.g., data min..max)
    /// * `range` - Output value range (e.g., screen 0..width)
    ///
    /// # Examples
    /// ```
    /// use redblue::ui::Scale;
    ///
    /// // Map temperature -10°C..40°C to screen height 0..100 pixels
    /// let scale = Scale::new(-10.0..40.0, 0.0..100.0);
    ///
    /// assert_eq!(scale.linear(15.0), 50.0); // 15°C → 50 pixels (middle)
    /// ```
    pub fn new(domain: Range<f32>, range: Range<f32>) -> Self {
        Self { domain, range }
    }

    /// Transform value from domain to range (linear interpolation)
    ///
    /// Formula: `range_start + (x - domain_start) / domain_width * range_width`
    ///
    /// Result is clamped to range bounds.
    ///
    /// # Arguments
    /// * `x` - Input value in domain space
    ///
    /// # Returns
    /// Mapped value in range space, clamped to [range.start, range.end]
    ///
    /// # Examples
    /// ```
    /// let scale = Scale::new(0.0..10.0, 0.0..100.0);
    ///
    /// assert_eq!(scale.linear(5.0), 50.0);  // middle → middle
    /// assert_eq!(scale.linear(0.0), 0.0);    // min → min
    /// assert_eq!(scale.linear(10.0), 100.0); // max → max
    /// assert_eq!(scale.linear(-5.0), 0.0);   // below min → clamped to min
    /// assert_eq!(scale.linear(15.0), 100.0); // above max → clamped to max
    /// ```
    pub fn linear(&self, x: f32) -> f32 {
        let domain_width = self.domain.end - self.domain.start;
        let range_width = self.range.end - self.range.start;

        // Calculate percentage through domain
        let t = (x - self.domain.start) / domain_width;

        // Map to range and clamp
        let result = self.range.start + t * range_width;
        result.max(self.range.start).min(self.range.end)
    }

    /// Transform value from range to domain (inverse linear interpolation)
    ///
    /// This is the inverse operation of `linear()`.
    ///
    /// Formula: `domain_start + (i - range_start) / range_width * domain_width`
    ///
    /// Result is clamped to domain bounds.
    ///
    /// # Arguments
    /// * `i` - Input value in range space (e.g., pixel coordinate)
    ///
    /// # Returns
    /// Mapped value in domain space, clamped to [domain.start, domain.end]
    ///
    /// # Examples
    /// ```
    /// let scale = Scale::new(0.0..10.0, 0.0..100.0);
    ///
    /// assert_eq!(scale.inv_linear(50.0), 5.0);  // middle → middle
    /// assert_eq!(scale.inv_linear(0.0), 0.0);    // min → min
    /// assert_eq!(scale.inv_linear(100.0), 10.0); // max → max
    /// ```
    pub fn inv_linear(&self, i: f32) -> f32 {
        let domain_width = self.domain.end - self.domain.start;
        let range_width = self.range.end - self.range.start;

        // Calculate percentage through range
        let t = (i - self.range.start) / range_width;

        // Map to domain and clamp
        let result = self.domain.start + t * domain_width;
        result.max(self.domain.start).min(self.domain.end)
    }

    /// Get the domain range
    pub fn domain(&self) -> &Range<f32> {
        &self.domain
    }

    /// Get the range range
    pub fn range(&self) -> &Range<f32> {
        &self.range
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linear_scaling() {
        let scale = Scale::new(0.0..10.0, 0.0..100.0);

        assert_eq!(scale.linear(0.0), 0.0);
        assert_eq!(scale.linear(5.0), 50.0);
        assert_eq!(scale.linear(10.0), 100.0);
    }

    #[test]
    fn test_inverse_scaling() {
        let scale = Scale::new(0.0..10.0, 0.0..100.0);

        assert_eq!(scale.inv_linear(0.0), 0.0);
        assert_eq!(scale.inv_linear(50.0), 5.0);
        assert_eq!(scale.inv_linear(100.0), 10.0);
    }

    #[test]
    fn test_roundtrip() {
        let scale = Scale::new(-5.0..15.0, 0.0..200.0);

        let x = 7.3;
        let y = scale.linear(x);
        let x2 = scale.inv_linear(y);

        assert!((x - x2).abs() < 0.001, "Expected {}, got {}", x, x2);
    }

    #[test]
    fn test_clamping() {
        let scale = Scale::new(0.0..10.0, 0.0..100.0);

        // Values outside domain should be clamped
        assert_eq!(scale.linear(-5.0), 0.0);
        assert_eq!(scale.linear(15.0), 100.0);

        // Values outside range should be clamped
        assert_eq!(scale.inv_linear(-50.0), 0.0);
        assert_eq!(scale.inv_linear(150.0), 10.0);
    }

    #[test]
    fn test_negative_domain() {
        let scale = Scale::new(-10.0..10.0, 0.0..100.0);

        assert_eq!(scale.linear(-10.0), 0.0);
        assert_eq!(scale.linear(0.0), 50.0);
        assert_eq!(scale.linear(10.0), 100.0);
    }

    #[test]
    fn test_textplots_example() {
        // From textplots-rs documentation:
        // Scale::new(0_f32..10_f32, -1_f32..1_f32).linear(1.0) == -0.8
        let scale = Scale::new(0.0..10.0, -1.0..1.0);
        let result = scale.linear(1.0);
        let expected = -0.8;

        assert!(
            (result - expected).abs() < 0.001,
            "Expected {}, got {}",
            expected,
            result
        );
    }

    #[test]
    fn test_textplots_inverse_example() {
        // From textplots-rs documentation:
        // Scale::new(0_f32..10_f32, -1_f32..1_f32).inv_linear(0.1) == 5.5
        let scale = Scale::new(0.0..10.0, -1.0..1.0);
        let result = scale.inv_linear(0.1);
        let expected = 5.5;

        assert!(
            (result - expected).abs() < 0.001,
            "Expected {}, got {}",
            expected,
            result
        );
    }
}
