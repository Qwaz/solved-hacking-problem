package android.support.v7.p014a;

import android.support.v7.p015b.C0243l;
import android.support.v7.view.menu.C0203j;
import android.support.v7.view.menu.C0264i;
import android.view.MenuItem;

/* renamed from: android.support.v7.a.ay */
final class ay implements C0203j {
    final /* synthetic */ av f674a;

    private ay(av avVar) {
        this.f674a = avVar;
    }

    public void m1812a(C0264i c0264i) {
        if (this.f674a.f666b == null) {
            return;
        }
        if (this.f674a.f665a.m2622i()) {
            this.f674a.f666b.onPanelClosed(C0243l.AppCompatTheme_ratingBarStyleSmall, c0264i);
        } else if (this.f674a.f666b.onPreparePanel(0, null, c0264i)) {
            this.f674a.f666b.onMenuOpened(C0243l.AppCompatTheme_ratingBarStyleSmall, c0264i);
        }
    }

    public boolean m1813a(C0264i c0264i, MenuItem menuItem) {
        return false;
    }
}
