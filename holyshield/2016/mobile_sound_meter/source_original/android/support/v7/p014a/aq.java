package android.support.v7.p014a;

import android.content.Context;
import android.content.res.Resources.Theme;
import android.content.res.TypedArray;
import android.os.Bundle;
import android.support.v7.p015b.C0233b;
import android.support.v7.p015b.C0240i;
import android.support.v7.p015b.C0242k;
import android.support.v7.p015b.C0243l;
import android.support.v7.view.C0249e;
import android.support.v7.view.menu.C0207y;
import android.support.v7.view.menu.C0260z;
import android.support.v7.view.menu.C0264i;
import android.support.v7.view.menu.C0269g;
import android.util.TypedValue;
import android.view.View;
import android.view.ViewGroup;

/* renamed from: android.support.v7.a.aq */
final class aq {
    int f635a;
    int f636b;
    int f637c;
    int f638d;
    int f639e;
    int f640f;
    ViewGroup f641g;
    View f642h;
    View f643i;
    C0264i f644j;
    C0269g f645k;
    Context f646l;
    boolean f647m;
    boolean f648n;
    boolean f649o;
    public boolean f650p;
    boolean f651q;
    boolean f652r;
    Bundle f653s;

    aq(int i) {
        this.f635a = i;
        this.f651q = false;
    }

    C0260z m1770a(C0207y c0207y) {
        if (this.f644j == null) {
            return null;
        }
        if (this.f645k == null) {
            this.f645k = new C0269g(this.f646l, C0240i.abc_list_menu_item_layout);
            this.f645k.m2199a(c0207y);
            this.f644j.m2111a(this.f645k);
        }
        return this.f645k.m2195a(this.f641g);
    }

    void m1771a(Context context) {
        TypedValue typedValue = new TypedValue();
        Theme newTheme = context.getResources().newTheme();
        newTheme.setTo(context.getTheme());
        newTheme.resolveAttribute(C0233b.actionBarPopupTheme, typedValue, true);
        if (typedValue.resourceId != 0) {
            newTheme.applyStyle(typedValue.resourceId, true);
        }
        newTheme.resolveAttribute(C0233b.panelMenuListTheme, typedValue, true);
        if (typedValue.resourceId != 0) {
            newTheme.applyStyle(typedValue.resourceId, true);
        } else {
            newTheme.applyStyle(C0242k.Theme_AppCompat_CompactMenu, true);
        }
        Context c0249e = new C0249e(context, 0);
        c0249e.getTheme().setTo(newTheme);
        this.f646l = c0249e;
        TypedArray obtainStyledAttributes = c0249e.obtainStyledAttributes(C0243l.AppCompatTheme);
        this.f636b = obtainStyledAttributes.getResourceId(C0243l.AppCompatTheme_panelBackground, 0);
        this.f640f = obtainStyledAttributes.getResourceId(C0243l.AppCompatTheme_android_windowAnimationStyle, 0);
        obtainStyledAttributes.recycle();
    }

    void m1772a(C0264i c0264i) {
        if (c0264i != this.f644j) {
            if (this.f644j != null) {
                this.f644j.m2122b(this.f645k);
            }
            this.f644j = c0264i;
            if (c0264i != null && this.f645k != null) {
                c0264i.m2111a(this.f645k);
            }
        }
    }

    public boolean m1773a() {
        return this.f642h == null ? false : this.f643i != null || this.f645k.m2196a().getCount() > 0;
    }
}
