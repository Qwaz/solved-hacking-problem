package android.support.v7.p014a;

import android.support.v7.p015b.C0243l;
import android.support.v7.view.menu.C0207y;
import android.support.v7.view.menu.C0264i;

/* renamed from: android.support.v7.a.ax */
final class ax implements C0207y {
    final /* synthetic */ av f672a;
    private boolean f673b;

    private ax(av avVar) {
        this.f672a = avVar;
    }

    public void m1810a(C0264i c0264i, boolean z) {
        if (!this.f673b) {
            this.f673b = true;
            this.f672a.f665a.m2627n();
            if (this.f672a.f666b != null) {
                this.f672a.f666b.onPanelClosed(C0243l.AppCompatTheme_ratingBarStyleSmall, c0264i);
            }
            this.f673b = false;
        }
    }

    public boolean m1811a(C0264i c0264i) {
        if (this.f672a.f666b == null) {
            return false;
        }
        this.f672a.f666b.onMenuOpened(C0243l.AppCompatTheme_ratingBarStyleSmall, c0264i);
        return true;
    }
}
