//! Terminal graphics demonstration
//!
//! Shows various chart types using the redblue terminal graphics library.
//!
//! Run with:
//! ```
//! cargo run --example ui-graphs-demo
//! ```

use redblue::ui::colors::colors::{BLUE, GREEN, RED, YELLOW};
use redblue::ui::{Chart, ColorPlot, Plot, Shape};

fn main() {
    println!("\n=== redblue Terminal Graphics Demo ===\n");

    // Demo 1: Sine wave (continuous function)
    println!("1. Sine Wave (Continuous Function)");
    println!("y = sin(x)\n");
    Chart::default()
        .lineplot(&Shape::Continuous(Box::new(|x| x.sin())))
        .display();

    // Demo 2: Multiple functions with colors
    println!("\n2. Multiple Functions (Colored)");
    println!("y = sin(x), y = cos(x), y = sin(x)/2\n");
    Chart::new(180, 60, -5.0, 5.0)
        .linecolorplot(&Shape::Continuous(Box::new(|x| x.sin())), RED)
        .linecolorplot(&Shape::Continuous(Box::new(|x| x.cos())), GREEN)
        .linecolorplot(&Shape::Continuous(Box::new(|x| x.sin() / 2.0)), BLUE)
        .display();

    // Demo 3: Discrete points
    println!("\n3. Scatter Plot (Discrete Points)");
    let points = vec![
        (0.0, 1.0),
        (1.0, 3.0),
        (2.0, 2.0),
        (3.0, 4.0),
        (4.0, 3.5),
        (5.0, 5.0),
    ];
    Chart::new(120, 40, -0.5, 5.5)
        .linecolorplot(&Shape::Points(&points), YELLOW)
        .display();

    // Demo 4: Line plot connecting points
    println!("\n4. Line Plot (Connected Points)");
    Chart::new(120, 40, -0.5, 5.5)
        .linecolorplot(&Shape::Lines(&points), GREEN)
        .display();

    // Demo 5: Bar chart
    println!("\n5. Bar Chart");
    let bars = vec![
        (0.0, 1.5),
        (1.0, 2.8),
        (2.0, 1.2),
        (3.0, 3.5),
        (4.0, 2.1),
    ];
    Chart::new(120, 40, -0.5, 4.5)
        .linecolorplot(&Shape::Bars(&bars), BLUE)
        .display();

    // Demo 6: Step plot
    println!("\n6. Step Plot");
    Chart::new(120, 40, -0.5, 5.5)
        .linecolorplot(&Shape::Steps(&points), RED)
        .display();

    // Demo 7: Complex function
    println!("\n7. Complex Function");
    println!("y = sin(x) / x (sinc function)\n");
    Chart::new(180, 60, -10.0, 10.0)
        .linecolorplot(
            &Shape::Continuous(Box::new(|x| {
                if x.abs() < 0.001 {
                    1.0
                } else {
                    x.sin() / x
                }
            })),
            GREEN,
        )
        .display();

    // Demo 8: Fixed Y-axis range
    println!("\n8. Fixed Y-axis Range");
    println!("y = x^2 with y range [0, 10]\n");
    Chart::new_with_y_range(120, 40, -5.0, 5.0, 0.0, 10.0)
        .linecolorplot(&Shape::Continuous(Box::new(|x| x * x)), YELLOW)
        .display();

    println!("\n=== Demo Complete ===\n");
    println!("✓ Zero external dependencies");
    println!("✓ Braille patterns for high resolution (2×4 pixels per char)");
    println!("✓ TrueColor support (16M colors)");
    println!("✓ Pure Rust implementation\n");
}
