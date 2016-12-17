package android.support.p000a.p001a;

import android.graphics.drawable.Drawable;
import android.graphics.drawable.Drawable.Callback;

/* renamed from: android.support.a.a.c */
class C0003c implements Callback {
    final /* synthetic */ C0002b f11a;

    C0003c(C0002b c0002b) {
        this.f11a = c0002b;
    }

    public void invalidateDrawable(Drawable drawable) {
        this.f11a.invalidateSelf();
    }

    public void scheduleDrawable(Drawable drawable, Runnable runnable, long j) {
        this.f11a.scheduleSelf(runnable, j);
    }

    public void unscheduleDrawable(Drawable drawable, Runnable runnable) {
        this.f11a.unscheduleSelf(runnable);
    }
}
