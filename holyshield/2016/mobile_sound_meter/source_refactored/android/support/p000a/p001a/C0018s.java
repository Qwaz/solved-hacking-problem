package android.support.p000a.p001a;

import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.graphics.Bitmap;
import android.graphics.Bitmap.Config;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.PorterDuff.Mode;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.Drawable.ConstantState;

/* renamed from: android.support.a.a.s */
class C0018s extends ConstantState {
    int f76a;
    C0017r f77b;
    ColorStateList f78c;
    Mode f79d;
    boolean f80e;
    Bitmap f81f;
    ColorStateList f82g;
    Mode f83h;
    int f84i;
    boolean f85j;
    boolean f86k;
    Paint f87l;

    public C0018s() {
        this.f78c = null;
        this.f79d = C0011l.f21b;
        this.f77b = new C0017r();
    }

    public C0018s(C0018s c0018s) {
        this.f78c = null;
        this.f79d = C0011l.f21b;
        if (c0018s != null) {
            this.f76a = c0018s.f76a;
            this.f77b = new C0017r(c0018s.f77b);
            if (c0018s.f77b.f72m != null) {
                this.f77b.f72m = new Paint(c0018s.f77b.f72m);
            }
            if (c0018s.f77b.f71l != null) {
                this.f77b.f71l = new Paint(c0018s.f77b.f71l);
            }
            this.f78c = c0018s.f78c;
            this.f79d = c0018s.f79d;
            this.f80e = c0018s.f80e;
        }
    }

    public Paint m66a(ColorFilter colorFilter) {
        if (!m69a() && colorFilter == null) {
            return null;
        }
        if (this.f87l == null) {
            this.f87l = new Paint();
            this.f87l.setFilterBitmap(true);
        }
        this.f87l.setAlpha(this.f77b.m61a());
        this.f87l.setColorFilter(colorFilter);
        return this.f87l;
    }

    public void m67a(int i, int i2) {
        this.f81f.eraseColor(0);
        this.f77b.m64a(new Canvas(this.f81f), i, i2, null);
    }

    public void m68a(Canvas canvas, ColorFilter colorFilter, Rect rect) {
        canvas.drawBitmap(this.f81f, null, rect, m66a(colorFilter));
    }

    public boolean m69a() {
        return this.f77b.m61a() < 255;
    }

    public void m70b(int i, int i2) {
        if (this.f81f == null || !m73c(i, i2)) {
            this.f81f = Bitmap.createBitmap(i, i2, Config.ARGB_8888);
            this.f86k = true;
        }
    }

    public boolean m71b() {
        return !this.f86k && this.f82g == this.f78c && this.f83h == this.f79d && this.f85j == this.f80e && this.f84i == this.f77b.m61a();
    }

    public void m72c() {
        this.f82g = this.f78c;
        this.f83h = this.f79d;
        this.f84i = this.f77b.m61a();
        this.f85j = this.f80e;
        this.f86k = false;
    }

    public boolean m73c(int i, int i2) {
        return i == this.f81f.getWidth() && i2 == this.f81f.getHeight();
    }

    public int getChangingConfigurations() {
        return this.f76a;
    }

    public Drawable newDrawable() {
        return new C0011l();
    }

    public Drawable newDrawable(Resources resources) {
        return new C0011l();
    }
}
