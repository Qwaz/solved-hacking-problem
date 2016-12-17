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
import me.daei.soundmeter.Obfuscator2;
import me.daei.soundmeter.DensityCalculator;
import me.daei.soundmeter.StaticHolder;

public class SoundDiscView extends ImageView {
    private float widthRatio;
    private float heightRatio;
    private int width;
    private int height;
    private Matrix matrix;
    private Bitmap bmp;
    private Paint paint;

    public SoundDiscView(Context context) {
        super(context);
        this.matrix = new Matrix();
        this.paint = new Paint();
    }

    public SoundDiscView(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.matrix = new Matrix();
        this.paint = new Paint();
    }

    private float adjust(float f) {
        return ((f - 85.0f) * 5.0f) / 3.0f;
    }

    private void initBmp() {
        Bitmap decodeResource = BitmapFactory.decodeResource(getResources(), 2130837580);
        int resourceWidth = decodeResource.getWidth();
        int resourceHeight = decodeResource.getHeight();
        this.width = getWidth();
        this.height = getHeight();
        this.widthRatio = ((float) this.width) / ((float) resourceWidth);
        this.heightRatio = ((float) this.height) / ((float) resourceHeight);
        this.matrix.postScale(this.widthRatio, this.heightRatio);
        this.bmp = Bitmap.createBitmap(decodeResource, 0, 0, resourceWidth, resourceHeight, this.matrix, true);
        this.paint = new Paint();
        this.paint.setTextSize(22.0f * DensityCalculator.getDensity(getContext()));
        this.paint.setAntiAlias(true);
        this.paint.setTextAlign(Align.CENTER);
        this.paint.setColor(-1);
    }

    public void updateView() {
        postInvalidateDelayed(20);
    }

    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        if (this.bmp == null) {
            initBmp();
        }
        this.matrix.setRotate(adjust(StaticHolder.now), (float) (this.width / 2), (float) ((this.height * 215) / 460));
        canvas.drawBitmap(this.bmp, this.matrix, this.paint);
        if (StaticHolder.now > 55.0f && StaticHolder.now < 65.0f) {
            canvas.drawText("H", (float) (this.width / 2), (float) ((this.height * 36) / 46), this.paint);
        }
        if (StaticHolder.now > 65.0f && StaticHolder.now < 70.0f) {
            canvas.drawText("HS", (float) (this.width / 2), (float) ((this.height * 36) / 46), this.paint);
        }
        if (StaticHolder.now > 70.0f && StaticHolder.now < 80.0f) {
            canvas.drawText("HS{", (float) (this.width / 2), (float) ((this.height * 36) / 46), this.paint);
        }
        if (((int) StaticHolder.now) > 80 && ((int) StaticHolder.now) < 82) {
            canvas.drawText("" + ((char) ((int) Obfuscator2.encrypt((float) ((int) StaticHolder.now)))), (float) (this.width / 2), (float) ((this.height * 36) / 46), this.paint);
        }
        if (((int) StaticHolder.now) > 82 && ((int) StaticHolder.now) < 84) {
            canvas.drawText("" + ((char) ((int) Obfuscator2.encrypt((float) ((int) StaticHolder.now)))), (float) (this.width / 2), (float) ((this.height * 36) / 46), this.paint);
        }
        if (((int) StaticHolder.now) > 84 && ((int) StaticHolder.now) < 86) {
            canvas.drawText("" + ((char) ((int) Obfuscator2.encrypt((float) ((int) StaticHolder.now)))), (float) (this.width / 2), (float) ((this.height * 36) / 46), this.paint);
        }
        if (((int) StaticHolder.now) > 86 && ((int) StaticHolder.now) < 88) {
            canvas.drawText("" + ((char) ((int) Obfuscator2.encrypt((float) ((int) StaticHolder.now)))), (float) (this.width / 2), (float) ((this.height * 36) / 46), this.paint);
        }
        if (((int) StaticHolder.now) > 88 && ((int) StaticHolder.now) < 90) {
            canvas.drawText("" + ((char) ((int) Obfuscator2.encrypt((float) ((int) StaticHolder.now)))), (float) (this.width / 2), (float) ((this.height * 36) / 46), this.paint);
        }
        if (((int) StaticHolder.now) > 91 && ((int) StaticHolder.now) < 93) {
            canvas.drawText("" + ((char) ((int) Obfuscator2.encrypt((float) ((int) StaticHolder.now)))), (float) (this.width / 2), (float) ((this.height * 36) / 46), this.paint);
        }
        if (((int) StaticHolder.now) > 94 && ((int) StaticHolder.now) < 96) {
            canvas.drawText("" + ((char) ((int) Obfuscator2.encrypt((float) ((int) StaticHolder.now)))), (float) (this.width / 2), (float) ((this.height * 36) / 46), this.paint);
        }
        if (((int) StaticHolder.now) > 97 && ((int) StaticHolder.now) < 99) {
            canvas.drawText("" + ((char) ((int) Obfuscator2.encrypt((float) ((int) StaticHolder.now)))), (float) (this.width / 2), (float) ((this.height * 36) / 46), this.paint);
        }
        // 104, 106
        if (((int) StaticHolder.now) > C0243l.AppCompatTheme_editTextStyle && ((int) StaticHolder.now) < C0243l.AppCompatTheme_ratingBarStyle) {
            canvas.drawText("" + ((char) ((int) Obfuscator2.encrypt((float) ((int) StaticHolder.now)))), (float) (this.width / 2), (float) ((this.height * 36) / 46), this.paint);
        }
        // 108, 110
        if (((int) StaticHolder.now) > C0243l.AppCompatTheme_ratingBarStyleSmall && ((int) StaticHolder.now) < C0243l.AppCompatTheme_spinnerStyle) {
            canvas.drawText("" + ((char) ((int) Obfuscator2.encrypt((float) ((int) StaticHolder.now)))), (float) (this.width / 2), (float) ((this.height * 36) / 46), this.paint);
        }
        // 110, 112
        if (((int) StaticHolder.now) > C0243l.AppCompatTheme_spinnerStyle && ((int) StaticHolder.now) < 112) {
            canvas.drawText("" + ((char) ((int) Obfuscator2.encrypt((float) ((int) StaticHolder.now)))), (float) (this.width / 2), (float) ((this.height * 36) / 46), this.paint);
        }
        if (((int) StaticHolder.now) > 113 && ((int) StaticHolder.now) < 115) {
            canvas.drawText("}", (float) (this.width / 2), (float) ((this.height * 36) / 46), this.paint);
        }
    }

    protected void onMeasure(int i, int i2) {
        super.onMeasure(i, i2);
    }
}
