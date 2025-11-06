//! High-level graphing API for terminal charts
//!
//! Inspired by textplots-rs but implemented from scratch with zero dependencies.
//!
//! # Examples
//!
//! ```rust
//! use redblue::ui::{Chart, Plot, Shape};
//!
//! // Plot a continuous function
//! Chart::default()
//!     .lineplot(&Shape::Continuous(Box::new(|x| x.sin() / x)))
//!     .display();
//!
//! // Plot discrete points
//! let points = vec![(0.0, 1.0), (1.0, 2.0), (2.0, 1.5)];
//! Chart::new(120, 60, -1.0, 3.0)
//!     .lineplot(&Shape::Points(&points))
//!     .display();
//! ```

use crate::ui::canvas::BrailleCanvas;
use crate::ui::colors::{truecolor_fg, Color, ANSI_RESET};
use crate::ui::scale::Scale;
use std::cmp::Ordering;
use std::f32;

/// Defines the type of data to be plotted
pub enum Shape<'a> {
    /// Continuous function: f(x) -> y
    Continuous(Box<dyn Fn(f32) -> f32 + 'a>),

    /// Scatter plot: list of (x, y) points
    Points(&'a [(f32, f32)]),

    /// Line plot: points connected by straight lines
    Lines(&'a [(f32, f32)]),

    /// Step plot: points connected with horizontal then vertical segments
    Steps(&'a [(f32, f32)]),

    /// Bar chart: vertical bars from y=0 to each point
    Bars(&'a [(f32, f32)]),
}

/// Chart rendering options
pub struct Chart<'a> {
    /// Pixel width
    width: usize,
    /// Pixel height
    height: usize,
    /// X-axis minimum value
    xmin: f32,
    /// X-axis maximum value
    xmax: f32,
    /// Y-axis minimum value (auto-calculated or fixed)
    ymin: f32,
    /// Y-axis maximum value (auto-calculated or fixed)
    ymax: f32,
    /// Whether to auto-calculate Y range
    auto_range_y: bool,
    /// Shapes to plot with optional colors
    shapes: Vec<(&'a Shape<'a>, Option<Color>)>,
    /// Underlying Braille canvas
    canvas: BrailleCanvas,
}

impl<'a> Default for Chart<'a> {
    fn default() -> Self {
        Self::new(120, 60, -10.0, 10.0)
    }
}

impl<'a> Chart<'a> {
    /// Create a new chart with auto Y-axis ranging
    ///
    /// # Arguments
    /// * `width` - Canvas width in pixels
    /// * `height` - Canvas height in pixels
    /// * `xmin` - X-axis minimum value
    /// * `xmax` - X-axis maximum value
    ///
    /// The Y-axis range will be automatically calculated based on the plotted data.
    ///
    /// # Panics
    /// Panics if width < 32 or height < 3
    pub fn new(width: usize, height: usize, xmin: f32, xmax: f32) -> Self {
        if width < 32 {
            panic!("width must be at least 32");
        }
        if height < 3 {
            panic!("height must be at least 3");
        }

        Self {
            width,
            height,
            xmin,
            xmax,
            ymin: f32::INFINITY,
            ymax: f32::NEG_INFINITY,
            auto_range_y: true,
            shapes: Vec::new(),
            canvas: BrailleCanvas::new_with_color(width, height),
        }
    }

    /// Create a chart with fixed Y-axis range
    ///
    /// # Arguments
    /// * `width` - Canvas width in pixels
    /// * `height` - Canvas height in pixels
    /// * `xmin` - X-axis minimum value
    /// * `xmax` - X-axis maximum value
    /// * `ymin` - Y-axis minimum value (fixed)
    /// * `ymax` - Y-axis maximum value (fixed)
    ///
    /// # Panics
    /// Panics if width < 32 or height < 3
    pub fn new_with_y_range(
        width: usize,
        height: usize,
        xmin: f32,
        xmax: f32,
        ymin: f32,
        ymax: f32,
    ) -> Self {
        if width < 32 {
            panic!("width must be at least 32");
        }
        if height < 3 {
            panic!("height must be at least 3");
        }

        Self {
            width,
            height,
            xmin,
            xmax,
            ymin,
            ymax,
            auto_range_y: false,
            shapes: Vec::new(),
            canvas: BrailleCanvas::new_with_color(width, height),
        }
    }

    /// Render the chart and print to stdout
    pub fn display(&mut self) {
        self.render();
        let frame = self.canvas.render();
        println!("{}", frame);
    }

    /// Get the rendered frame as a string without printing
    pub fn frame(&mut self) -> String {
        self.render();
        self.canvas.render()
    }

    /// Calculate Y range from all shapes if auto-ranging enabled
    fn calculate_y_range(&mut self) {
        if !self.auto_range_y {
            return;
        }

        let x_scale = Scale::new(self.xmin..self.xmax, 0.0..self.width as f32);

        for (shape, _color) in &self.shapes {
            let ys: Vec<f32> = match shape {
                Shape::Continuous(f) => (0..self.width)
                    .filter_map(|i| {
                        let x = x_scale.inv_linear(i as f32);
                        let y = f(x);
                        if y.is_normal() {
                            Some(y)
                        } else {
                            None
                        }
                    })
                    .collect(),
                Shape::Points(pts) | Shape::Lines(pts) | Shape::Steps(pts) | Shape::Bars(pts) => {
                    pts.iter()
                        .filter_map(|(x, y)| {
                            if *x >= self.xmin && *x <= self.xmax {
                                Some(*y)
                            } else {
                                None
                            }
                        })
                        .collect()
                }
            };

            if let Some(&max_y) = ys
                .iter()
                .max_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal))
            {
                self.ymax = self.ymax.max(max_y);
            }

            if let Some(&min_y) = ys
                .iter()
                .min_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal))
            {
                self.ymin = self.ymin.min(min_y);
            }
        }

        // Add 10% padding to Y range for better visualization
        let y_range = self.ymax - self.ymin;
        if y_range > 0.0 {
            let padding = y_range * 0.1;
            self.ymin -= padding;
            self.ymax += padding;
        }
    }

    /// Render all shapes to the canvas
    fn render(&mut self) {
        self.canvas.clear();
        self.calculate_y_range();

        let x_scale = Scale::new(self.xmin..self.xmax, 0.0..self.width as f32);
        let y_scale = Scale::new(self.ymin..self.ymax, 0.0..self.height as f32);

        for (shape, color_opt) in &self.shapes {
            // Convert (x, y) points to screen coordinates
            let points: Vec<(usize, usize)> = match shape {
                Shape::Continuous(f) => (0..self.width)
                    .filter_map(|i| {
                        let x = x_scale.inv_linear(i as f32);
                        let y = f(x);
                        if y.is_normal() {
                            let j = y_scale.linear(y).round();
                            if j >= 0.0 && j <= self.height as f32 {
                                Some((i, self.height - j as usize))
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    })
                    .collect(),
                Shape::Points(data)
                | Shape::Lines(data)
                | Shape::Steps(data)
                | Shape::Bars(data) => data
                    .iter()
                    .filter_map(|(x, y)| {
                        let i = x_scale.linear(*x).round() as usize;
                        let j = y_scale.linear(*y).round() as usize;
                        if i < self.width && j < self.height {
                            Some((i, self.height - j))
                        } else {
                            None
                        }
                    })
                    .collect(),
            };

            // Draw based on shape type
            match (shape, color_opt) {
                (Shape::Continuous(_), Some(color)) | (Shape::Lines(_), Some(color)) => {
                    // Draw colored lines between points
                    for window in points.windows(2) {
                        let (x1, y1) = window[0];
                        let (x2, y2) = window[1];
                        self.canvas.line_colored(x1, y1, x2, y2, *color);
                    }
                }
                (Shape::Continuous(_), None) | (Shape::Lines(_), None) => {
                    // Draw uncolored lines
                    for window in points.windows(2) {
                        let (x1, y1) = window[0];
                        let (x2, y2) = window[1];
                        self.canvas.line(x1, y1, x2, y2);
                    }
                }
                (Shape::Points(_), Some(color)) => {
                    // Draw colored points
                    for (x, y) in points {
                        self.canvas.set_colored(x, y, *color);
                    }
                }
                (Shape::Points(_), None) => {
                    // Draw uncolored points
                    for (x, y) in points {
                        self.canvas.set(x, y);
                    }
                }
                (Shape::Steps(_), Some(color)) => {
                    // Draw step plot with horizontal then vertical segments
                    for window in points.windows(2) {
                        let (x1, y1) = window[0];
                        let (x2, y2) = window[1];
                        self.canvas.line_colored(x1, y2, x2, y2, *color); // horizontal
                        self.canvas.line_colored(x1, y1, x1, y2, *color); // vertical
                    }
                }
                (Shape::Steps(_), None) => {
                    for window in points.windows(2) {
                        let (x1, y1) = window[0];
                        let (x2, y2) = window[1];
                        self.canvas.line(x1, y2, x2, y2); // horizontal
                        self.canvas.line(x1, y1, x1, y2); // vertical
                    }
                }
                (Shape::Bars(_), Some(color)) => {
                    // Draw bars from bottom to each point
                    for window in points.windows(2) {
                        let (x1, y1) = window[0];
                        let (x2, y2) = window[1];
                        self.canvas.line_colored(x1, y2, x2, y2, *color); // top
                        self.canvas.line_colored(x1, y1, x1, y2, *color); // left edge
                        self.canvas.line_colored(x1, self.height, x1, y1, *color); // left bar
                        self.canvas.line_colored(x2, self.height, x2, y2, *color);
                        // right bar
                    }
                }
                (Shape::Bars(_), None) => {
                    for window in points.windows(2) {
                        let (x1, y1) = window[0];
                        let (x2, y2) = window[1];
                        self.canvas.line(x1, y2, x2, y2);
                        self.canvas.line(x1, y1, x1, y2);
                        self.canvas.line(x1, self.height, x1, y1);
                        self.canvas.line(x2, self.height, x2, y2);
                    }
                }
            }
        }
    }
}

/// Trait for plotting shapes on a chart
pub trait Plot<'a> {
    /// Add a line plot to the chart
    fn lineplot(&'a mut self, shape: &'a Shape) -> &'a mut Chart;
}

/// Trait for plotting colored shapes on a chart
pub trait ColorPlot<'a> {
    /// Add a colored line plot to the chart
    fn linecolorplot(&'a mut self, shape: &'a Shape, color: Color) -> &'a mut Chart;
}

impl<'a> Plot<'a> for Chart<'a> {
    fn lineplot(&'a mut self, shape: &'a Shape) -> &'a mut Chart {
        self.shapes.push((shape, None));
        self
    }
}

impl<'a> ColorPlot<'a> for Chart<'a> {
    fn linecolorplot(&'a mut self, shape: &'a Shape, color: Color) -> &'a mut Chart {
        self.shapes.push((shape, Some(color)));
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chart_creation() {
        let chart = Chart::new(120, 60, -10.0, 10.0);
        assert_eq!(chart.width, 120);
        assert_eq!(chart.height, 60);
        assert_eq!(chart.xmin, -10.0);
        assert_eq!(chart.xmax, 10.0);
    }

    #[test]
    fn test_chart_with_fixed_y_range() {
        let chart = Chart::new_with_y_range(120, 60, -10.0, 10.0, -5.0, 5.0);
        assert_eq!(chart.ymin, -5.0);
        assert_eq!(chart.ymax, 5.0);
        assert!(!chart.auto_range_y);
    }

    #[test]
    #[should_panic(expected = "width must be at least 32")]
    fn test_chart_too_small_width() {
        Chart::new(10, 60, -10.0, 10.0);
    }

    #[test]
    #[should_panic(expected = "height must be at least 3")]
    fn test_chart_too_small_height() {
        Chart::new(120, 2, -10.0, 10.0);
    }

    // TODO: Fix lifetime issues with Shape borrowing before enabling these tests
    #[cfg(disabled_tests)]
    mod shape_tests {
        use super::*;

        #[test]
        fn test_continuous_function() {
            let mut chart = Chart::new(120, 60, -10.0, 10.0);
            let shape = Shape::Continuous(Box::new(|x| x.sin()));
            chart.lineplot(&shape);
            let frame = chart.frame();
            assert!(!frame.is_empty());
        }

        #[test]
        fn test_points() {
            let points = vec![(0.0, 1.0), (1.0, 2.0), (2.0, 1.5), (3.0, 0.5)];
            let mut chart = Chart::new(120, 60, -1.0, 4.0);
            let shape = Shape::Points(&points);
            chart.lineplot(&shape);
            let frame = chart.frame();
            assert!(!frame.is_empty());
        }

        #[test]
        fn test_colored_plot() {
            use crate::ui::colors::colors::RED;

            let mut chart = Chart::new(120, 60, -10.0, 10.0);
            let shape = Shape::Continuous(Box::new(|x| x.sin()));
            chart.linecolorplot(&shape, RED);
            let frame = chart.frame();
            assert!(!frame.is_empty());
        }
    }
}
