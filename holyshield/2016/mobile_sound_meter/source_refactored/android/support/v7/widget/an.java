package android.support.v7.widget;

import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.PorterDuff.Mode;
import android.graphics.drawable.Drawable;
import android.os.Build.VERSION;
import android.support.v4.p006c.p007a.C0062a;
import android.support.v4.widget.C0180e;
import android.support.v7.p015b.C0243l;
import android.util.AttributeSet;
import android.widget.CompoundButton;

class an {
    private final CompoundButton f1298a;
    private final ao f1299b;
    private ColorStateList f1300c;
    private Mode f1301d;
    private boolean f1302e;
    private boolean f1303f;
    private boolean f1304g;

    an(CompoundButton compoundButton, ao aoVar) {
        this.f1300c = null;
        this.f1301d = null;
        this.f1302e = false;
        this.f1303f = false;
        this.f1298a = compoundButton;
        this.f1299b = aoVar;
    }

    int m2483a(int i) {
        if (VERSION.SDK_INT >= 17) {
            return i;
        }
        Drawable a = C0180e.m1542a(this.f1298a);
        return a != null ? i + a.getIntrinsicWidth() : i;
    }

    ColorStateList m2484a() {
        return this.f1300c;
    }

    void m2485a(ColorStateList colorStateList) {
        this.f1300c = colorStateList;
        this.f1302e = true;
        m2490d();
    }

    void m2486a(Mode mode) {
        this.f1301d = mode;
        this.f1303f = true;
        m2490d();
    }

    void m2487a(AttributeSet attributeSet, int i) {
        TypedArray obtainStyledAttributes = this.f1298a.getContext().obtainStyledAttributes(attributeSet, C0243l.CompoundButton, i, 0);
        try {
            if (obtainStyledAttributes.hasValue(C0243l.CompoundButton_android_button)) {
                int resourceId = obtainStyledAttributes.getResourceId(C0243l.CompoundButton_android_button, 0);
                if (resourceId != 0) {
                    this.f1298a.setButtonDrawable(this.f1299b.m2520a(this.f1298a.getContext(), resourceId));
                }
            }
            if (obtainStyledAttributes.hasValue(C0243l.CompoundButton_buttonTint)) {
                C0180e.m1543a(this.f1298a, obtainStyledAttributes.getColorStateList(C0243l.CompoundButton_buttonTint));
            }
            if (obtainStyledAttributes.hasValue(C0243l.CompoundButton_buttonTintMode)) {
                C0180e.m1544a(this.f1298a, bt.m2632a(obtainStyledAttributes.getInt(C0243l.CompoundButton_buttonTintMode, -1), null));
            }
            obtainStyledAttributes.recycle();
        } catch (Throwable th) {
            obtainStyledAttributes.recycle();
        }
    }

    Mode m2488b() {
        return this.f1301d;
    }

    void m2489c() {
        if (this.f1304g) {
            this.f1304g = false;
            return;
        }
        this.f1304g = true;
        m2490d();
    }

    void m2490d() {
        Drawable a = C0180e.m1542a(this.f1298a);
        if (a == null) {
            return;
        }
        if (this.f1302e || this.f1303f) {
            a = C0062a.m467f(a).mutate();
            if (this.f1302e) {
                C0062a.m458a(a, this.f1300c);
            }
            if (this.f1303f) {
                C0062a.m461a(a, this.f1301d);
            }
            if (a.isStateful()) {
                a.setState(this.f1298a.getDrawableState());
            }
            this.f1298a.setButtonDrawable(a);
        }
    }
}
