package android.support.v7.widget;

import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.PorterDuff.Mode;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.os.Build.VERSION;
import android.support.v4.p004h.bu;
import android.support.v7.p015b.C0243l;
import android.util.AttributeSet;
import android.view.View;

class aj {
    private final View f1285a;
    private final ao f1286b;
    private df f1287c;
    private df f1288d;
    private df f1289e;

    aj(View view, ao aoVar) {
        this.f1285a = view;
        this.f1286b = aoVar;
    }

    private boolean m2472b(Drawable drawable) {
        return VERSION.SDK_INT == 21 && (drawable instanceof GradientDrawable);
    }

    private void m2473c(Drawable drawable) {
        if (this.f1289e == null) {
            this.f1289e = new df();
        }
        df dfVar = this.f1289e;
        dfVar.m2708a();
        ColorStateList n = bu.m1005n(this.f1285a);
        if (n != null) {
            dfVar.f1519d = true;
            dfVar.f1516a = n;
        }
        Mode o = bu.m1006o(this.f1285a);
        if (o != null) {
            dfVar.f1518c = true;
            dfVar.f1517b = o;
        }
        if (dfVar.f1519d || dfVar.f1518c) {
            ao.m2500a(drawable, dfVar, this.f1285a.getDrawableState());
        }
    }

    ColorStateList m2474a() {
        return this.f1288d != null ? this.f1288d.f1516a : null;
    }

    void m2475a(int i) {
        m2481b(this.f1286b != null ? this.f1286b.m2522b(this.f1285a.getContext(), i) : null);
    }

    void m2476a(ColorStateList colorStateList) {
        if (this.f1288d == null) {
            this.f1288d = new df();
        }
        this.f1288d.f1516a = colorStateList;
        this.f1288d.f1519d = true;
        m2482c();
    }

    void m2477a(Mode mode) {
        if (this.f1288d == null) {
            this.f1288d = new df();
        }
        this.f1288d.f1517b = mode;
        this.f1288d.f1518c = true;
        m2482c();
    }

    void m2478a(Drawable drawable) {
        m2481b(null);
    }

    void m2479a(AttributeSet attributeSet, int i) {
        TypedArray obtainStyledAttributes = this.f1285a.getContext().obtainStyledAttributes(attributeSet, C0243l.ViewBackgroundHelper, i, 0);
        try {
            if (obtainStyledAttributes.hasValue(C0243l.ViewBackgroundHelper_android_background)) {
                ColorStateList b = this.f1286b.m2522b(this.f1285a.getContext(), obtainStyledAttributes.getResourceId(C0243l.ViewBackgroundHelper_android_background, -1));
                if (b != null) {
                    m2481b(b);
                }
            }
            if (obtainStyledAttributes.hasValue(C0243l.ViewBackgroundHelper_backgroundTint)) {
                bu.m982a(this.f1285a, obtainStyledAttributes.getColorStateList(C0243l.ViewBackgroundHelper_backgroundTint));
            }
            if (obtainStyledAttributes.hasValue(C0243l.ViewBackgroundHelper_backgroundTintMode)) {
                bu.m983a(this.f1285a, bt.m2632a(obtainStyledAttributes.getInt(C0243l.ViewBackgroundHelper_backgroundTintMode, -1), null));
            }
            obtainStyledAttributes.recycle();
        } catch (Throwable th) {
            obtainStyledAttributes.recycle();
        }
    }

    Mode m2480b() {
        return this.f1288d != null ? this.f1288d.f1517b : null;
    }

    void m2481b(ColorStateList colorStateList) {
        if (colorStateList != null) {
            if (this.f1287c == null) {
                this.f1287c = new df();
            }
            this.f1287c.f1516a = colorStateList;
            this.f1287c.f1519d = true;
        } else {
            this.f1287c = null;
        }
        m2482c();
    }

    void m2482c() {
        Drawable background = this.f1285a.getBackground();
        if (background == null) {
            return;
        }
        if (this.f1288d != null) {
            ao.m2500a(background, this.f1288d, this.f1285a.getDrawableState());
        } else if (this.f1287c != null) {
            ao.m2500a(background, this.f1287c, this.f1285a.getDrawableState());
        } else if (m2472b(background)) {
            m2473c(background);
        }
    }
}
