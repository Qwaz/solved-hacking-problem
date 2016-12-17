package android.support.v7.view;

import android.content.Context;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.os.Build.VERSION;
import android.support.v4.p004h.ct;
import android.support.v7.p015b.C0233b;
import android.support.v7.p015b.C0234c;
import android.support.v7.p015b.C0236e;
import android.support.v7.p015b.C0239h;
import android.support.v7.p015b.C0243l;
import android.view.ViewConfiguration;

/* renamed from: android.support.v7.view.a */
public class C0247a {
    private Context f847a;

    private C0247a(Context context) {
        this.f847a = context;
    }

    public static C0247a m1987a(Context context) {
        return new C0247a(context);
    }

    public int m1988a() {
        return this.f847a.getResources().getInteger(C0239h.abc_max_action_buttons);
    }

    public boolean m1989b() {
        return VERSION.SDK_INT >= 19 || !ct.m1177a(ViewConfiguration.get(this.f847a));
    }

    public int m1990c() {
        return this.f847a.getResources().getDisplayMetrics().widthPixels / 2;
    }

    public boolean m1991d() {
        return this.f847a.getApplicationInfo().targetSdkVersion >= 16 ? this.f847a.getResources().getBoolean(C0234c.abc_action_bar_embed_tabs) : this.f847a.getResources().getBoolean(C0234c.abc_action_bar_embed_tabs_pre_jb);
    }

    public int m1992e() {
        TypedArray obtainStyledAttributes = this.f847a.obtainStyledAttributes(null, C0243l.ActionBar, C0233b.actionBarStyle, 0);
        int layoutDimension = obtainStyledAttributes.getLayoutDimension(C0243l.ActionBar_height, 0);
        Resources resources = this.f847a.getResources();
        if (!m1991d()) {
            layoutDimension = Math.min(layoutDimension, resources.getDimensionPixelSize(C0236e.abc_action_bar_stacked_max_height));
        }
        obtainStyledAttributes.recycle();
        return layoutDimension;
    }

    public boolean m1993f() {
        return this.f847a.getApplicationInfo().targetSdkVersion < 14;
    }

    public int m1994g() {
        return this.f847a.getResources().getDimensionPixelSize(C0236e.abc_action_bar_stacked_tab_max_width);
    }
}
