//! APEX 0.1.0 terminal palette, vendored subset of unified-platform/design-system/apex_tokens.rs.
//! Source: https://github.com/onixus/unified-platform/issues/117
use ratatui::style::Color;
#[derive(Clone, Copy)]
pub struct Palette {
    pub bg_canvas: Color,
    pub surface_1: Color,
    pub surface_2: Color,
    pub border_control: Color,
    pub text_primary: Color,
    pub text_secondary: Color,
    pub accent: Color,
    pub focus_ring: Color,
    pub success: Color,
    pub success_subtle: Color,
}
pub const DARK: Palette = Palette {
    bg_canvas: Color::Rgb(8, 11, 17),
    surface_1: Color::Rgb(13, 19, 31),
    surface_2: Color::Rgb(19, 27, 44),
    border_control: Color::Rgb(100, 116, 139),
    text_primary: Color::Rgb(248, 250, 252),
    text_secondary: Color::Rgb(148, 163, 184),
    accent: Color::Rgb(56, 189, 248),
    focus_ring: Color::Rgb(125, 211, 252),
    success: Color::Rgb(52, 211, 153),
    success_subtle: Color::Rgb(18, 42, 46),
};
pub const LIGHT: Palette = Palette {
    bg_canvas: Color::Rgb(245, 247, 251),
    surface_1: Color::Rgb(255, 255, 255),
    surface_2: Color::Rgb(241, 245, 249),
    border_control: Color::Rgb(118, 133, 155),
    text_primary: Color::Rgb(15, 23, 42),
    text_secondary: Color::Rgb(71, 85, 105),
    accent: Color::Rgb(3, 105, 161),
    focus_ring: Color::Rgb(2, 132, 199),
    success: Color::Rgb(4, 120, 87),
    success_subtle: Color::Rgb(237, 246, 243),
};

#[derive(Clone, Copy, Default)]
pub enum Theme {
    #[default]
    Dark,
    Light,
    System,
}
impl Theme {
    pub fn name(self) -> &'static str {
        match self {
            Self::Dark => "dark",
            Self::Light => "light",
            Self::System => "system",
        }
    }
    pub fn next(self) -> Self {
        match self {
            Self::Dark => Self::Light,
            Self::Light => Self::System,
            Self::System => Self::Dark,
        }
    }
    pub fn palette(self) -> Palette {
        match self {
            Self::Light => LIGHT,
            Self::System
                if std::env::var("COLORFGBG")
                    .ok()
                    .and_then(|s| s.rsplit(';').next().and_then(|n| n.parse::<u8>().ok()))
                    .is_some_and(|n| n == 7 || n == 15) =>
            {
                LIGHT
            }
            _ => DARK,
        }
    }
}
