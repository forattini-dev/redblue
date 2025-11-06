//! Braille canvas for high-resolution terminal graphics
//!
//! Uses Unicode Braille patterns (U+2800-U+28FF) to achieve 2×4 pixel resolution
//! per character cell, giving us 8x higher resolution than ASCII art.
//!
//! ## Braille Pattern Encoding
//!
//! Each Braille character represents an 8-dot pattern in a 2×4 grid:
//! ```text
//! ┌─┬─┐
//! │0│3│
//! │1│4│
//! │2│5│
//! │6│7│
//! └─┴─┘
//! ```
//!
//! Unicode codepoint: U+2800 + bit pattern
//! - Bit 0 (LSB) = top-left dot
//! - Bit 7 (MSB) = bottom-right dot
//!
//! ## Examples
//!
//! - `⠀` (U+2800) = blank (no dots)
//! - `⠁` (U+2801) = dot 0 only
//! - `⠃` (U+2803) = dots 0,1 (0x03 = 0b0000_0011)
//! - `⣿` (U+28FF) = all 8 dots (0xFF = 0b1111_1111)

const BRAILLE_BASE: u32 = 0x2800;

// Bit positions for 2×4 Braille dot pattern
const BRAILLE_DOTS: [[u8; 4]; 2] = [
    [0, 1, 2, 6], // left column (dots 0,1,2,6)
    [3, 4, 5, 7], // right column (dots 3,4,5,7)
];

/// High-resolution canvas using Braille Unicode patterns
#[derive(Clone)]
pub struct BrailleCanvas {
    /// Canvas width in Braille characters (each char = 2 pixels wide)
    char_width: usize,
    /// Canvas height in Braille characters (each char = 4 pixels high)
    char_height: usize,
    /// Total pixel width (char_width * 2)
    pixel_width: usize,
    /// Total pixel height (char_height * 4)
    pixel_height: usize,
    /// Pixel state grid: pixels[y * pixel_width + x]
    /// true = dot enabled, false = dot disabled
    pixels: Vec<bool>,
    /// Optional color per pixel (None = default color)
    colors: Option<Vec<Option<(u8, u8, u8)>>>,
}

impl BrailleCanvas {
    /// Create a new Braille canvas with the specified pixel dimensions
    ///
    /// # Arguments
    /// * `width` - Canvas width in pixels (will be rounded up to nearest even number)
    /// * `height` - Canvas height in pixels (will be rounded up to nearest multiple of 4)
    ///
    /// # Examples
    /// ```
    /// let canvas = BrailleCanvas::new(120, 60);
    /// // Creates 60×15 character grid (120 pixels ÷ 2, 60 pixels ÷ 4)
    /// ```
    pub fn new(width: usize, height: usize) -> Self {
        // Round up to character boundaries
        let char_width = (width + 1) / 2;
        let char_height = (height + 3) / 4;
        let pixel_width = char_width * 2;
        let pixel_height = char_height * 4;
        let pixel_count = pixel_width * pixel_height;

        Self {
            char_width,
            char_height,
            pixel_width,
            pixel_height,
            pixels: vec![false; pixel_count],
            colors: None,
        }
    }

    /// Create canvas with color support enabled
    pub fn new_with_color(width: usize, height: usize) -> Self {
        let mut canvas = Self::new(width, height);
        canvas.colors = Some(vec![None; canvas.pixels.len()]);
        canvas
    }

    /// Set a pixel at the given coordinates
    ///
    /// # Arguments
    /// * `x` - X coordinate (0 to pixel_width-1)
    /// * `y` - Y coordinate (0 to pixel_height-1)
    ///
    /// Returns `true` if pixel was set, `false` if out of bounds
    pub fn set(&mut self, x: usize, y: usize) -> bool {
        if x >= self.pixel_width || y >= self.pixel_height {
            return false;
        }
        let idx = y * self.pixel_width + x;
        self.pixels[idx] = true;
        true
    }

    /// Set a pixel with color
    pub fn set_colored(&mut self, x: usize, y: usize, color: (u8, u8, u8)) -> bool {
        if x >= self.pixel_width || y >= self.pixel_height {
            return false;
        }
        let idx = y * self.pixel_width + x;
        self.pixels[idx] = true;
        if let Some(colors) = &mut self.colors {
            colors[idx] = Some(color);
        }
        true
    }

    /// Clear a pixel at the given coordinates
    pub fn unset(&mut self, x: usize, y: usize) -> bool {
        if x >= self.pixel_width || y >= self.pixel_height {
            return false;
        }
        let idx = y * self.pixel_width + x;
        self.pixels[idx] = false;
        true
    }

    /// Clear all pixels on the canvas
    pub fn clear(&mut self) {
        for pixel in &mut self.pixels {
            *pixel = false;
        }
        if let Some(colors) = &mut self.colors {
            for color in colors {
                *color = None;
            }
        }
    }

    /// Draw a line from (x1, y1) to (x2, y2) using Bresenham's algorithm
    ///
    /// This is the classic line drawing algorithm that uses only integer arithmetic
    /// and avoids floating-point math for efficiency.
    pub fn line(&mut self, x1: usize, y1: usize, x2: usize, y2: usize) {
        let dx = (x2 as isize - x1 as isize).abs();
        let dy = (y2 as isize - y1 as isize).abs();
        let sx = if x1 < x2 { 1 } else { -1 };
        let sy = if y1 < y2 { 1 } else { -1 };
        let mut err = dx - dy;
        let mut x = x1 as isize;
        let mut y = y1 as isize;

        loop {
            self.set(x as usize, y as usize);

            if x == x2 as isize && y == y2 as isize {
                break;
            }

            let e2 = 2 * err;
            if e2 > -dy {
                err -= dy;
                x += sx;
            }
            if e2 < dx {
                err += dx;
                y += sy;
            }
        }
    }

    /// Draw a colored line
    pub fn line_colored(
        &mut self,
        x1: usize,
        y1: usize,
        x2: usize,
        y2: usize,
        color: (u8, u8, u8),
    ) {
        let dx = (x2 as isize - x1 as isize).abs();
        let dy = (y2 as isize - y1 as isize).abs();
        let sx = if x1 < x2 { 1 } else { -1 };
        let sy = if y1 < y2 { 1 } else { -1 };
        let mut err = dx - dy;
        let mut x = x1 as isize;
        let mut y = y1 as isize;

        loop {
            self.set_colored(x as usize, y as usize, color);

            if x == x2 as isize && y == y2 as isize {
                break;
            }

            let e2 = 2 * err;
            if e2 > -dy {
                err -= dy;
                x += sx;
            }
            if e2 < dx {
                err += dx;
                y += sy;
            }
        }
    }

    /// Convert 8-bit dot pattern to Braille character
    ///
    /// Bit pattern corresponds to dot positions:
    /// - Bit 0 = dot 0 (top-left)
    /// - Bit 1 = dot 1 (middle-left)
    /// - Bit 2 = dot 2 (bottom-left)
    /// - Bit 3 = dot 3 (top-right)
    /// - Bit 4 = dot 4 (middle-right)
    /// - Bit 5 = dot 5 (bottom-right)
    /// - Bit 6 = dot 6 (extra-bottom-left)
    /// - Bit 7 = dot 7 (extra-bottom-right)
    #[inline]
    fn dots_to_braille(pattern: u8) -> char {
        // Unicode Braille: U+2800 + dot pattern
        char::from_u32(BRAILLE_BASE + pattern as u32).unwrap_or('?')
    }

    /// Render the canvas to a string
    ///
    /// Returns a multi-line string where each character is a Braille pattern
    /// representing a 2×4 pixel region.
    pub fn render(&self) -> String {
        let mut output = String::with_capacity(self.char_height * (self.char_width + 1));

        for char_y in 0..self.char_height {
            for char_x in 0..self.char_width {
                let mut pattern: u8 = 0;

                // Sample 2×4 pixel region for this character
                for px in 0..2 {
                    for py in 0..4 {
                        let pixel_x = char_x * 2 + px;
                        let pixel_y = char_y * 4 + py;
                        let idx = pixel_y * self.pixel_width + pixel_x;

                        if self.pixels[idx] {
                            let bit_pos = BRAILLE_DOTS[px][py];
                            pattern |= 1 << bit_pos;
                        }
                    }
                }

                output.push(Self::dots_to_braille(pattern));
            }
            output.push('\n');
        }

        output
    }

    /// Get canvas dimensions in pixels
    pub fn dimensions(&self) -> (usize, usize) {
        (self.pixel_width, self.pixel_height)
    }

    /// Get canvas dimensions in characters
    pub fn char_dimensions(&self) -> (usize, usize) {
        (self.char_width, self.char_height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canvas_creation() {
        let canvas = BrailleCanvas::new(120, 60);
        assert_eq!(canvas.dimensions(), (120, 60));
        assert_eq!(canvas.char_dimensions(), (60, 15));
    }

    #[test]
    fn test_set_pixel() {
        let mut canvas = BrailleCanvas::new(10, 10);
        assert!(canvas.set(0, 0));
        assert!(canvas.set(9, 9));
        assert!(!canvas.set(10, 10)); // out of bounds
    }

    #[test]
    fn test_braille_encoding() {
        let mut canvas = BrailleCanvas::new(2, 4);

        // Set top-left pixel (bit 0)
        canvas.set(0, 0);
        let rendered = canvas.render();
        assert!(rendered.contains('⠁')); // U+2801 = 0x01

        // Set both left column pixels
        canvas.clear();
        canvas.set(0, 0);
        canvas.set(0, 1);
        let rendered = canvas.render();
        assert!(rendered.contains('⠃')); // U+2803 = 0x03
    }

    #[test]
    fn test_line_drawing() {
        let mut canvas = BrailleCanvas::new(20, 20);

        // Horizontal line
        canvas.line(0, 10, 19, 10);

        // Vertical line
        canvas.line(10, 0, 10, 19);

        // Diagonal line
        canvas.line(0, 0, 19, 19);

        let rendered = canvas.render();
        assert!(rendered.len() > 0);
        assert!(rendered.contains('\n'));
    }

    #[test]
    fn test_clear() {
        let mut canvas = BrailleCanvas::new(10, 10);
        canvas.set(5, 5);
        canvas.clear();

        // All pixels should be empty
        for &pixel in &canvas.pixels {
            assert!(!pixel);
        }
    }
}
