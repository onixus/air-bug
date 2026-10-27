package dev.onixus.aircrack;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Path;
import android.view.View;

/** Lucide (ISC): shield-check, file, circle-check, triangle-alert, sun-moon. 24px viewbox. */
final class LucideIcon extends View {
    private final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final String kind;
    LucideIcon(Context context, String kind, int color) {
        super(context); this.kind = kind;
        paint.setColor(color); paint.setStyle(Paint.Style.STROKE);
        paint.setStrokeWidth(2); paint.setStrokeCap(Paint.Cap.ROUND); paint.setStrokeJoin(Paint.Join.ROUND);
        setImportantForAccessibility(IMPORTANT_FOR_ACCESSIBILITY_NO);
    }
    @Override protected void onDraw(Canvas canvas) {
        canvas.save(); canvas.scale(getWidth()/24f, getHeight()/24f);
        Path p = new Path();
        switch (kind) {
            case "shield":
                p.moveTo(12,22); p.cubicTo(12,22,3,18,3,11); p.lineTo(3,5); p.lineTo(12,2); p.lineTo(21,5); p.lineTo(21,11); p.cubicTo(21,18,12,22,12,22);
                canvas.drawPath(p,paint); p.reset(); p.moveTo(9,12); p.lineTo(11,14); p.lineTo(15,10); break;
            case "check":
                canvas.drawCircle(12,12,10,paint); p.moveTo(8,12); p.lineTo(11,15); p.lineTo(16,9); break;
            case "alert":
                p.moveTo(12,3); p.lineTo(22,21); p.lineTo(2,21); p.close(); canvas.drawPath(p,paint); p.reset();
                p.moveTo(12,9); p.lineTo(12,13); p.moveTo(12,17); p.lineTo(12,17.1f); break;
            case "theme":
                canvas.drawCircle(12,12,4,paint);
                for(int i=0;i<8;i++){double a=i*Math.PI/4; canvas.drawLine(12+(float)Math.cos(a)*8,12+(float)Math.sin(a)*8,12+(float)Math.cos(a)*10,12+(float)Math.sin(a)*10,paint);} break;
            default:
                p.moveTo(14,2); p.lineTo(6,2); p.quadTo(4,2,4,4); p.lineTo(4,20); p.quadTo(4,22,6,22); p.lineTo(18,22); p.quadTo(20,22,20,20); p.lineTo(20,8); p.close();
                p.moveTo(14,2); p.lineTo(14,8); p.lineTo(20,8); p.moveTo(8,13); p.lineTo(16,13); p.moveTo(8,17); p.lineTo(14,17);
        }
        canvas.drawPath(p,paint); canvas.restore();
    }
}
