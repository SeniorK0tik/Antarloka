//! Minimal QR rendering straight onto the egui painter.
//!
//! Drawing rectangles avoids depending on egui's texture API, which changes
//! shape between releases, and keeps the code obvious.

use egui::{Color32, Rect, Sense, Ui, Vec2};

/// Draw `data` as a QR code occupying a square of `size` logical pixels.
pub fn draw(ui: &mut Ui, data: &str, size: f32) -> Result<(), String> {
    let code = qrcode::QrCode::new(data.as_bytes()).map_err(|e| e.to_string())?;
    let colors = code.to_colors();
    let width = code.width();
    if width == 0 {
        return Err("пустой QR-код".into());
    }

    // A quiet zone of four modules is required by the spec for reliable scans.
    let quiet = 4usize;
    let total = width + quiet * 2;
    let module = size / total as f32;

    let (rect, _resp) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 0.0, Color32::WHITE);

    for y in 0..width {
        for x in 0..width {
            if colors[y * width + x] == qrcode::Color::Dark {
                let min =
                    rect.min + Vec2::new((x + quiet) as f32 * module, (y + quiet) as f32 * module);
                // +0.5 avoids hairline gaps between neighbouring modules.
                painter.rect_filled(
                    Rect::from_min_size(min, Vec2::splat(module + 0.5)),
                    0.0,
                    Color32::BLACK,
                );
            }
        }
    }
    Ok(())
}
