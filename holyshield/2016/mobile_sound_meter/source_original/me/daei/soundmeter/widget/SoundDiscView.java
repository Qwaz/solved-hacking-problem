package me.daei.soundmeter.widget;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Canvas;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.Paint.Align;
import android.support.v7.p015b.C0243l;
import android.util.AttributeSet;
import android.widget.ImageView;
import me.daei.soundmeter.C0308a;
import me.daei.soundmeter.C0313f;
import me.daei.soundmeter.C0315h;

public class SoundDiscView extends ImageView {
    private float f1635a;
    private float f1636b;
    private int f1637c;
    private int f1638d;
    private Matrix f1639e;
    private Bitmap f1640f;
    private Paint f1641g;

    public SoundDiscView(Context context) {
        super(context);
        this.f1639e = new Matrix();
        this.f1641g = new Paint();
    }

    public SoundDiscView(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.f1639e = new Matrix();
        this.f1641g = new Paint();
    }

    private float m2881a(float f) {
        return ((f - 85.0f) * 5.0f) / 3.0f;
    }

    private void m2882b() {
        Bitmap decodeResource = BitmapFactory.decodeResource(getResources(), 2130837580);
        int width = decodeResource.getWidth();
        int height = decodeResource.getHeight();
        this.f1637c = getWidth();
        this.f1638d = getHeight();
        this.f1635a = ((float) this.f1637c) / ((float) width);
        this.f1636b = ((float) this.f1638d) / ((float) height);
        this.f1639e.postScale(this.f1635a, this.f1636b);
        this.f1640f = Bitmap.createBitmap(decodeResource, 0, 0, width, height, this.f1639e, true);
        this.f1641g = new Paint();
        this.f1641g.setTextSize(22.0f * C0313f.m2879a(getContext()));
        this.f1641g.setAntiAlias(true);
        this.f1641g.setTextAlign(Align.CENTER);
        this.f1641g.setColor(-1);
    }

    public void m2883a() {
        postInvalidateDelayed(20);
    }

    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        if (this.f1640f == null) {
            m2882b();
        }
        this.f1639e.setRotate(m2881a(C0315h.f1631a), (float) (this.f1637c / 2), (float) ((this.f1638d * 215) / 460));
        canvas.drawBitmap(this.f1640f, this.f1639e, this.f1641g);
        if (C0315h.f1631a > 55.0f && C0315h.f1631a < 65.0f) {
            canvas.drawText("H", (float) (this.f1637c / 2), (float) ((this.f1638d * 36) / 46), this.f1641g);
        }
        if (C0315h.f1631a > 65.0f && C0315h.f1631a < 70.0f) {
            canvas.drawText("HS", (float) (this.f1637c / 2), (float) ((this.f1638d * 36) / 46), this.f1641g);
        }
        if (C0315h.f1631a > 70.0f && C0315h.f1631a < 80.0f) {
            canvas.drawText("HS{", (float) (this.f1637c / 2), (float) ((this.f1638d * 36) / 46), this.f1641g);
        }
        if (((int) C0315h.f1631a) > 80 && ((int) C0315h.f1631a) < 82) {
            canvas.drawText("" + ((char) ((int) C0308a.m2871a((float) ((int) C0315h.f1631a)))), (float) (this.f1637c / 2), (float) ((this.f1638d * 36) / 46), this.f1641g);
        }
        if (((int) C0315h.f1631a) > 82 && ((int) C0315h.f1631a) < 84) {
            canvas.drawText("" + ((char) ((int) C0308a.m2871a((float) ((int) C0315h.f1631a)))), (float) (this.f1637c / 2), (float) ((this.f1638d * 36) / 46), this.f1641g);
        }
        if (((int) C0315h.f1631a) > 84 && ((int) C0315h.f1631a) < 86) {
            canvas.drawText("" + ((char) ((int) C0308a.m2871a((float) ((int) C0315h.f1631a)))), (float) (this.f1637c / 2), (float) ((this.f1638d * 36) / 46), this.f1641g);
        }
        if (((int) C0315h.f1631a) > 86 && ((int) C0315h.f1631a) < 88) {
            canvas.drawText("" + ((char) ((int) C0308a.m2871a((float) ((int) C0315h.f1631a)))), (float) (this.f1637c / 2), (float) ((this.f1638d * 36) / 46), this.f1641g);
        }
        if (((int) C0315h.f1631a) > 88 && ((int) C0315h.f1631a) < 90) {
            canvas.drawText("" + ((char) ((int) C0308a.m2871a((float) ((int) C0315h.f1631a)))), (float) (this.f1637c / 2), (float) ((this.f1638d * 36) / 46), this.f1641g);
        }
        if (((int) C0315h.f1631a) > 91 && ((int) C0315h.f1631a) < 93) {
            canvas.drawText("" + ((char) ((int) C0308a.m2871a((float) ((int) C0315h.f1631a)))), (float) (this.f1637c / 2), (float) ((this.f1638d * 36) / 46), this.f1641g);
        }
        if (((int) C0315h.f1631a) > 94 && ((int) C0315h.f1631a) < 96) {
            canvas.drawText("" + ((char) ((int) C0308a.m2871a((float) ((int) C0315h.f1631a)))), (float) (this.f1637c / 2), (float) ((this.f1638d * 36) / 46), this.f1641g);
        }
        if (((int) C0315h.f1631a) > 97 && ((int) C0315h.f1631a) < 99) {
            canvas.drawText("" + ((char) ((int) C0308a.m2871a((float) ((int) C0315h.f1631a)))), (float) (this.f1637c / 2), (float) ((this.f1638d * 36) / 46), this.f1641g);
        }
        if (((int) C0315h.f1631a) > C0243l.AppCompatTheme_editTextStyle && ((int) C0315h.f1631a) < C0243l.AppCompatTheme_ratingBarStyle) {
            canvas.drawText("" + ((char) ((int) C0308a.m2871a((float) ((int) C0315h.f1631a)))), (float) (this.f1637c / 2), (float) ((this.f1638d * 36) / 46), this.f1641g);
        }
        if (((int) C0315h.f1631a) > C0243l.AppCompatTheme_ratingBarStyleSmall && ((int) C0315h.f1631a) < C0243l.AppCompatTheme_spinnerStyle) {
            canvas.drawText("" + ((char) ((int) C0308a.m2871a((float) ((int) C0315h.f1631a)))), (float) (this.f1637c / 2), (float) ((this.f1638d * 36) / 46), this.f1641g);
        }
        if (((int) C0315h.f1631a) > C0243l.AppCompatTheme_spinnerStyle && ((int) C0315h.f1631a) < 112) {
            canvas.drawText("" + ((char) ((int) C0308a.m2871a((float) ((int) C0315h.f1631a)))), (float) (this.f1637c / 2), (float) ((this.f1638d * 36) / 46), this.f1641g);
        }
        if (((int) C0315h.f1631a) > 113 && ((int) C0315h.f1631a) < 115) {
            canvas.drawText("}", (float) (this.f1637c / 2), (float) ((this.f1638d * 36) / 46), this.f1641g);
        }
    }

    protected void onMeasure(int i, int i2) {
        super.onMeasure(i, i2);
    }
}
