package android.support.p000a.p001a;

import android.content.res.Resources;
import android.content.res.Resources.Theme;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.Drawable.ConstantState;

/* renamed from: android.support.a.a.e */
class C0005e extends ConstantState {
    private final ConstantState f16a;

    public C0005e(ConstantState constantState) {
        this.f16a = constantState;
    }

    public boolean canApplyTheme() {
        return this.f16a.canApplyTheme();
    }

    public int getChangingConfigurations() {
        return this.f16a.getChangingConfigurations();
    }

    public Drawable newDrawable() {
        C0002b c0002b = new C0002b();
        c0002b.a = this.f16a.newDrawable();
        c0002b.a.setCallback(c0002b.f10e);
        return c0002b;
    }

    public Drawable newDrawable(Resources resources) {
        C0002b c0002b = new C0002b();
        c0002b.a = this.f16a.newDrawable(resources);
        c0002b.a.setCallback(c0002b.f10e);
        return c0002b;
    }

    public Drawable newDrawable(Resources resources, Theme theme) {
        C0002b c0002b = new C0002b();
        c0002b.a = this.f16a.newDrawable(resources, theme);
        c0002b.a.setCallback(c0002b.f10e);
        return c0002b;
    }
}
