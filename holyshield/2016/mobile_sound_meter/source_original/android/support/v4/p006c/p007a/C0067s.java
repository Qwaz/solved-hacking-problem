package android.support.v4.p006c.p007a;

import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.graphics.PorterDuff.Mode;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.Drawable.ConstantState;

/* renamed from: android.support.v4.c.a.s */
public abstract class C0067s extends ConstantState {
    int f351a;
    ConstantState f352b;
    ColorStateList f353c;
    Mode f354d;

    C0067s(C0067s c0067s, Resources resources) {
        this.f353c = null;
        this.f354d = C0064r.f344a;
        if (c0067s != null) {
            this.f351a = c0067s.f351a;
            this.f352b = c0067s.f352b;
            this.f353c = c0067s.f353c;
            this.f354d = c0067s.f354d;
        }
    }

    boolean m488a() {
        return this.f352b != null;
    }

    public int getChangingConfigurations() {
        return (this.f352b != null ? this.f352b.getChangingConfigurations() : 0) | this.f351a;
    }

    public Drawable newDrawable() {
        return newDrawable(null);
    }

    public abstract Drawable newDrawable(Resources resources);
}
