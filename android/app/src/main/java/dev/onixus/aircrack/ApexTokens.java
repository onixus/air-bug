package dev.onixus.aircrack;

import android.content.Context;
import android.content.res.Configuration;
import android.graphics.Typeface;

/** Source: unified-platform#117. All color literals live here until apex-tokens ships. */
final class ApexTokens {
    static final int H1 = 24, H2 = 18, BODY = 14, BODY_SM = 13, CAPTION = 12, OVERLINE = 11;
    static final int HEADER = 56, SIDEBAR = 240, GRID = 4, RADIUS = 12;
    final int canvas, sunken, surface, field, hover, border, control, text, secondary, muted;
    final int accent, onAccent, focus, success, warning, danger, successSubtle, warningSubtle, dangerSubtle;
    final boolean dark;
    final Typeface inter, mono;
    ApexTokens(Context context, String mode) {
        dark = mode.equals("dark") || (mode.equals("system") &&
            (context.getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES);
        canvas = dark ? 0xff080b11 : 0xfff5f7fb;
        sunken = dark ? 0xff06090e : 0xffeef2f7;
        surface = dark ? 0xff0d131f : 0xffffffff;
        field = dark ? 0xff131b2c : 0xfff1f5f9;
        hover = dark ? 0xff1a253e : 0xffe2e8f0;
        border = dark ? 0xff1e293b : 0xffe2e8f0;
        control = dark ? 0xff64748b : 0xff76859b;
        text = dark ? 0xfff8fafc : 0xff0f172a;
        secondary = dark ? 0xff94a3b8 : 0xff475569;
        muted = dark ? 0xff8291a7 : 0xff5b6b80;
        accent = dark ? 0xff38bdf8 : 0xff0369a1;
        onAccent = dark ? 0xff04121f : 0xffffffff;
        focus = dark ? 0xff7dd3fc : 0xff0284c7;
        success = dark ? 0xff34d399 : 0xff047857;
        warning = dark ? 0xfffbbf24 : 0xffb45309;
        danger = dark ? 0xfffb7185 : 0xffbe123c;
        // Derived subtle surfaces (6% status on surface). 8% amber on light
        // would fall just below WCAG 4.5:1; checked by tests/check_apex.py.
        successSubtle = blend(surface, success);
        warningSubtle = blend(surface, warning);
        dangerSubtle = blend(surface, danger);
        inter = Typeface.createFromAsset(context.getAssets(), "fonts/Inter.ttf");
        mono = Typeface.createFromAsset(context.getAssets(), "fonts/JetBrainsMono.ttf");
    }
    private static int blend(int base, int color) {
        int r = (android.graphics.Color.red(base)*94 + android.graphics.Color.red(color)*6)/100;
        int g = (android.graphics.Color.green(base)*94 + android.graphics.Color.green(color)*6)/100;
        int b = (android.graphics.Color.blue(base)*94 + android.graphics.Color.blue(color)*6)/100;
        return android.graphics.Color.rgb(r,g,b);
    }
}
