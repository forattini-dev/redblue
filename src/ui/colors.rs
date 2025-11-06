//! ANSI color codes for terminal graphics (zero dependencies)
//!
//! Supports both 8-color and TrueColor (24-bit RGB) modes.

/// ANSI reset sequence
pub const ANSI_RESET: &str = "\x1b[0m";

/// RGB color tuple (red, green, blue)
pub type Color = (u8, u8, u8);

/// Create an RGB color
///
/// # Examples
/// ```
/// let red = rgb(255, 0, 0);
/// let green = rgb(0, 255, 0);
/// let blue = rgb(0, 0, 255);
/// ```
pub fn rgb(r: u8, g: u8, b: u8) -> Color {
    (r, g, b)
}

/// Generate ANSI TrueColor foreground sequence
///
/// Format: `\x1b[38;2;<r>;<g>;<b>m`
///
/// # Examples
/// ```
/// let red_fg = truecolor_fg(255, 0, 0);
/// println!("{}This text is red{}", red_fg, ANSI_RESET);
/// ```
pub fn truecolor_fg(r: u8, g: u8, b: u8) -> String {
    format!("\x1b[38;2;{};{};{}m", r, g, b)
}

/// Generate ANSI TrueColor background sequence
///
/// Format: `\x1b[48;2;<r>;<g>;<b>m`
pub fn truecolor_bg(r: u8, g: u8, b: u8) -> String {
    format!("\x1b[48;2;{};{};{}m", r, g, b)
}

/// Common color constants (RGB)
pub mod colors {
    use super::Color;

    pub const BLACK: Color = (0, 0, 0);
    pub const RED: Color = (255, 0, 0);
    pub const GREEN: Color = (0, 255, 0);
    pub const YELLOW: Color = (255, 255, 0);
    pub const BLUE: Color = (0, 0, 255);
    pub const MAGENTA: Color = (255, 0, 255);
    pub const CYAN: Color = (0, 255, 255);
    pub const WHITE: Color = (255, 255, 255);

    // Additional common colors
    pub const ORANGE: Color = (255, 165, 0);
    pub const PURPLE: Color = (128, 0, 128);
    pub const PINK: Color = (255, 192, 203);
    pub const BROWN: Color = (165, 42, 42);
    pub const GRAY: Color = (128, 128, 128);
    pub const DARK_GRAY: Color = (64, 64, 64);
    pub const LIGHT_GRAY: Color = (192, 192, 192);

    // Palette for multi-line charts (distinct colors)
    pub const CHART_COLORS: [Color; 8] = [RED, GREEN, BLUE, YELLOW, MAGENTA, CYAN, ORANGE, PURPLE];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rgb_creation() {
        let color = rgb(255, 128, 64);
        assert_eq!(color, (255, 128, 64));
    }

    #[test]
    fn test_truecolor_fg() {
        let red = truecolor_fg(255, 0, 0);
        assert_eq!(red, "\x1b[38;2;255;0;0m");
    }

    #[test]
    fn test_truecolor_bg() {
        let blue_bg = truecolor_bg(0, 0, 255);
        assert_eq!(blue_bg, "\x1b[48;2;0;0;255m");
    }

    #[test]
    fn test_color_constants() {
        use colors::*;

        assert_eq!(RED, (255, 0, 0));
        assert_eq!(GREEN, (0, 255, 0));
        assert_eq!(BLUE, (0, 0, 255));
        assert_eq!(WHITE, (255, 255, 255));
    }

    #[test]
    fn test_chart_colors() {
        use colors::CHART_COLORS;

        assert_eq!(CHART_COLORS.len(), 8);
        assert_eq!(CHART_COLORS[0], colors::RED);
        assert_eq!(CHART_COLORS[1], colors::GREEN);
    }
}
