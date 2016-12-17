package android.support.p000a.p001a;

import android.content.res.Resources;
import android.content.res.Resources.Theme;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.Drawable.ConstantState;
import android.graphics.drawable.VectorDrawable;

/* renamed from: android.support.a.a.t */
class C0019t extends ConstantState {
    private final ConstantState f88a;

    public C0019t(ConstantState constantState) {
        this.f88a = constantState;
    }

    public boolean canApplyTheme() {
        return this.f88a.canApplyTheme();
    }

    public int getChangingConfigurations() {
        return this.f88a.getChangingConfigurations();
    }

    public Drawable newDrawable() {
        Drawable c0011l = new C0011l();
        c0011l.a = (VectorDrawable) this.f88a.newDrawable();
        return c0011l;
    }

    public Drawable newDrawable(Resources resources) {
        Drawable c0011l = new C0011l();
        c0011l.a = (VectorDrawable) this.f88a.newDrawable(resources);
        return c0011l;
    }

    public Drawable newDrawable(Resources resources, Theme theme) {
        Drawable c0011l = new C0011l();
        c0011l.a = (VectorDrawable) this.f88a.newDrawable(resources, theme);
        return c0011l;
    }
}
