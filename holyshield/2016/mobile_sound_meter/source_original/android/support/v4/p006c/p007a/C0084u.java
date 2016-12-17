package android.support.v4.p006c.p007a;

import android.content.res.Resources;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.Drawable.ConstantState;

/* renamed from: android.support.v4.c.a.u */
class C0084u extends C0064r {
    C0084u(Drawable drawable) {
        super(drawable);
    }

    C0084u(C0067s c0067s, Resources resources) {
        super(c0067s, resources);
    }

    protected Drawable m563a(ConstantState constantState, Resources resources) {
        return constantState.newDrawable(resources);
    }

    C0067s m564b() {
        return new C0085v(this.b, null);
    }
}
