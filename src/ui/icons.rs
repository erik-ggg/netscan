//! Stroke icons, drawn in a 48x48 box centred on (0,0).

use crate::scan::model::DeviceKind;

pub fn paths(kind: DeviceKind) -> &'static [&'static str] {
    use DeviceKind::*;
    match kind {
        Internet => &[
            "M-18 0 a18 18 0 1 0 36 0 a18 18 0 1 0 -36 0",
            "M-18 0 H18",
            "M0 -18 C-12 -8 -12 8 0 18 C12 8 12 -8 0 -18",
            "M-15 -9 H15 M-15 9 H15",
        ],
        Router => &[
            "M-20 4 h40 v12 h-40 z",
            "M-13 10 h2 M-6 10 h2",
            "M-12 4 L-16 -14 M12 4 L16 -14",
            "M-8 -8 a11 11 0 0 1 16 0 M-4 -2 a5 5 0 0 1 8 0",
        ],
        Computer => &["M-15 -13 h30 v20 h-30 z", "M-21 12 h42 l-4 5 h-34 z", "M-6 12 h12"],
        Mobile => &["M-9 -19 h18 v38 h-18 z", "M-3 -15 h6", "M-3 15 h6"],
        Tablet => &["M-15 -18 h30 v36 h-30 z", "M-3 14 h6", "M-11 -14 h22 v24 h-22 z"],
        Tv => &["M-21 -15 h42 v26 h-42 z", "M-9 17 h18", "M0 11 v6", "M-16 -10 l6 0"],
        Media => &["M-20 -13 h40 v26 h-40 z", "M-5 -7 l11 7 l-11 7 z", "M-14 17 h28"],
        Iot => &[
            "M-9 -9 h18 v18 h-18 z",
            "M-4 -4 h8 v8 h-8 z",
            "M-5 -9 v-8 M5 -9 v-8 M-5 9 v8 M5 9 v8 M-9 -5 h-8 M-9 5 h-8 M9 -5 h8 M9 5 h8",
        ],
        Printer => &["M-11 -18 h22 v9 h-22 z", "M-19 -9 h38 v17 h-38 z", "M-11 3 h22 v15 h-22 z", "M-14 -3 h4"],
        Car => &[
            "M-21 8 v-8 l6 -2 l5 -9 h20 l5 9 l6 2 v8 z",
            "M-12 9 a4 4 0 1 0 8 0 a4 4 0 1 0 -8 0",
            "M8 9 a4 4 0 1 0 8 0 a4 4 0 1 0 -8 0",
            "M-6 -2 h12",
        ],
        Console => &[
            "M-17 -8 h34 l5 16 a4 4 0 0 1 -7 2 l-4 -6 h-22 l-4 6 a4 4 0 0 1 -7 -2 z",
            "M-11 -3 v7 M-14.5 0.5 h7",
            "M9 -2 h2 M13 2 h2",
        ],
        Unknown => &[
            "M-17 0 a17 17 0 1 0 34 0 a17 17 0 1 0 -34 0",
            "M-5 -6 a5 5 0 1 1 8 4 q-3 2 -3 5",
            "M0 10 v2",
        ],
    }
}

pub fn code(kind: DeviceKind) -> (&'static str, &'static str) {
    use DeviceKind::*;
    match kind {
        Internet => ("NET", "外部"),
        Router => ("GATEWAY", "中枢"),
        Computer => ("COMPUTER", "計算機"),
        Mobile => ("MOBILE", "携帯"),
        Tablet => ("TABLET", "端末"),
        Tv => ("DISPLAY", "映像"),
        Media => ("MEDIA", "媒体"),
        Iot => ("IOT NODE", "接点"),
        Printer => ("PRINTER", "印刷"),
        Car => ("VEHICLE", "車両"),
        Console => ("CONSOLE", "遊戯"),
        Unknown => ("UNKNOWN", "不明"),
    }
}
