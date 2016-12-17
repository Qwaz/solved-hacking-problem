package android.support.v7.widget;

import android.content.Context;
import android.content.res.Configuration;
import android.content.res.TypedArray;
import android.os.Build.VERSION;
import android.support.v4.p004h.az;
import android.support.v4.p004h.bu;
import android.support.v4.p004h.dh;
import android.support.v7.p015b.C0233b;
import android.support.v7.p015b.C0243l;
import android.util.AttributeSet;
import android.util.TypedValue;
import android.view.ContextThemeWrapper;
import android.view.MotionEvent;
import android.view.View;
import android.view.View.MeasureSpec;
import android.view.ViewGroup;

/* renamed from: android.support.v7.widget.a */
abstract class C0283a extends ViewGroup {
    protected final C0284b f1086a;
    protected final Context f1087b;
    protected ActionMenuView f1088c;
    protected C0294k f1089d;
    protected int f1090e;
    protected dh f1091f;
    private boolean f1092g;
    private boolean f1093h;

    C0283a(Context context) {
        this(context, null);
    }

    C0283a(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 0);
    }

    C0283a(Context context, AttributeSet attributeSet, int i) {
        super(context, attributeSet, i);
        this.f1086a = new C0284b(this);
        TypedValue typedValue = new TypedValue();
        if (!context.getTheme().resolveAttribute(C0233b.actionBarPopupTheme, typedValue, true) || typedValue.resourceId == 0) {
            this.f1087b = context;
        } else {
            this.f1087b = new ContextThemeWrapper(context, typedValue.resourceId);
        }
    }

    protected static int m2281a(int i, int i2, boolean z) {
        return z ? i - i2 : i + i2;
    }

    protected int m2284a(View view, int i, int i2, int i3) {
        view.measure(MeasureSpec.makeMeasureSpec(i, Integer.MIN_VALUE), i2);
        return Math.max(0, (i - view.getMeasuredWidth()) - i3);
    }

    protected int m2285a(View view, int i, int i2, int i3, boolean z) {
        int measuredWidth = view.getMeasuredWidth();
        int measuredHeight = view.getMeasuredHeight();
        int i4 = ((i3 - measuredHeight) / 2) + i2;
        if (z) {
            view.layout(i - measuredWidth, i4, i, measuredHeight + i4);
        } else {
            view.layout(i, i4, i + measuredWidth, measuredHeight + i4);
        }
        return z ? -measuredWidth : measuredWidth;
    }

    public dh m2286a(int i, long j) {
        if (this.f1091f != null) {
            this.f1091f.m1232b();
        }
        if (i == 0) {
            if (getVisibility() != 0) {
                bu.m991b((View) this, 0.0f);
            }
            dh a = bu.m1000i(this).m1225a(1.0f);
            a.m1226a(j);
            a.m1227a(this.f1086a.m2533a(a, i));
            return a;
        }
        a = bu.m1000i(this).m1225a(0.0f);
        a.m1226a(j);
        a.m1227a(this.f1086a.m2533a(a, i));
        return a;
    }

    public boolean m2287a() {
        return this.f1089d != null ? this.f1089d.m2828d() : false;
    }

    public int getAnimatedVisibility() {
        return this.f1091f != null ? this.f1086a.f1335a : getVisibility();
    }

    public int getContentHeight() {
        return this.f1090e;
    }

    protected void onConfigurationChanged(Configuration configuration) {
        if (VERSION.SDK_INT >= 8) {
            super.onConfigurationChanged(configuration);
        }
        TypedArray obtainStyledAttributes = getContext().obtainStyledAttributes(null, C0243l.ActionBar, C0233b.actionBarStyle, 0);
        setContentHeight(obtainStyledAttributes.getLayoutDimension(C0243l.ActionBar_height, 0));
        obtainStyledAttributes.recycle();
        if (this.f1089d != null) {
            this.f1089d.m2814a(configuration);
        }
    }

    public boolean onHoverEvent(MotionEvent motionEvent) {
        int a = az.m895a(motionEvent);
        if (a == 9) {
            this.f1093h = false;
        }
        if (!this.f1093h) {
            boolean onHoverEvent = super.onHoverEvent(motionEvent);
            if (a == 9 && !onHoverEvent) {
                this.f1093h = true;
            }
        }
        if (a == 10 || a == 3) {
            this.f1093h = false;
        }
        return true;
    }

    public boolean onTouchEvent(MotionEvent motionEvent) {
        int a = az.m895a(motionEvent);
        if (a == 0) {
            this.f1092g = false;
        }
        if (!this.f1092g) {
            boolean onTouchEvent = super.onTouchEvent(motionEvent);
            if (a == 0 && !onTouchEvent) {
                this.f1092g = true;
            }
        }
        if (a == 1 || a == 3) {
            this.f1092g = false;
        }
        return true;
    }

    public void setContentHeight(int i) {
        this.f1090e = i;
        requestLayout();
    }

    public void setVisibility(int i) {
        if (i != getVisibility()) {
            if (this.f1091f != null) {
                this.f1091f.m1232b();
            }
            super.setVisibility(i);
        }
    }
}
