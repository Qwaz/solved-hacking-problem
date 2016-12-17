package android.support.v7.widget;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.drawable.Drawable;
import android.os.Build.VERSION;
import android.support.v7.p015b.C0233b;
import android.support.v7.p015b.C0243l;
import android.support.v7.p018d.C0245a;
import android.text.method.PasswordTransformationMethod;
import android.util.AttributeSet;
import android.widget.TextView;

class bn {
    private static final int[] f1410b;
    private static final int[] f1411c;
    final TextView f1412a;
    private df f1413d;
    private df f1414e;
    private df f1415f;
    private df f1416g;

    static {
        f1410b = new int[]{16842804, 16843119, 16843117, 16843120, 16843118};
        f1411c = new int[]{C0233b.textAllCaps};
    }

    bn(TextView textView) {
        this.f1412a = textView;
    }

    static bn m2593a(TextView textView) {
        return VERSION.SDK_INT >= 17 ? new bo(textView) : new bn(textView);
    }

    protected static df m2594a(Context context, ao aoVar, int i) {
        ColorStateList b = aoVar.m2522b(context, i);
        if (b == null) {
            return null;
        }
        df dfVar = new df();
        dfVar.f1519d = true;
        dfVar.f1516a = b;
        return dfVar;
    }

    void m2595a() {
        if (this.f1413d != null || this.f1414e != null || this.f1415f != null || this.f1416g != null) {
            Drawable[] compoundDrawables = this.f1412a.getCompoundDrawables();
            m2597a(compoundDrawables[0], this.f1413d);
            m2597a(compoundDrawables[1], this.f1414e);
            m2597a(compoundDrawables[2], this.f1415f);
            m2597a(compoundDrawables[3], this.f1416g);
        }
    }

    void m2596a(Context context, int i) {
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(i, f1411c);
        if (obtainStyledAttributes.hasValue(0)) {
            m2599a(obtainStyledAttributes.getBoolean(0, false));
        }
        obtainStyledAttributes.recycle();
    }

    final void m2597a(Drawable drawable, df dfVar) {
        if (drawable != null && dfVar != null) {
            ao.m2500a(drawable, dfVar, this.f1412a.getDrawableState());
        }
    }

    void m2598a(AttributeSet attributeSet, int i) {
        int i2 = 1;
        Context context = this.f1412a.getContext();
        ao a = ao.m2497a();
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, f1410b, i, 0);
        int resourceId = obtainStyledAttributes.getResourceId(0, -1);
        if (obtainStyledAttributes.hasValue(1)) {
            this.f1413d = m2594a(context, a, obtainStyledAttributes.getResourceId(1, 0));
        }
        if (obtainStyledAttributes.hasValue(2)) {
            this.f1414e = m2594a(context, a, obtainStyledAttributes.getResourceId(2, 0));
        }
        if (obtainStyledAttributes.hasValue(3)) {
            this.f1415f = m2594a(context, a, obtainStyledAttributes.getResourceId(3, 0));
        }
        if (obtainStyledAttributes.hasValue(4)) {
            this.f1416g = m2594a(context, a, obtainStyledAttributes.getResourceId(4, 0));
        }
        obtainStyledAttributes.recycle();
        if (!(this.f1412a.getTransformationMethod() instanceof PasswordTransformationMethod)) {
            boolean z;
            int i3;
            boolean z2;
            if (resourceId != -1) {
                TypedArray obtainStyledAttributes2 = context.obtainStyledAttributes(resourceId, C0243l.TextAppearance);
                if (obtainStyledAttributes2.hasValue(C0243l.TextAppearance_textAllCaps)) {
                    z = obtainStyledAttributes2.getBoolean(C0243l.TextAppearance_textAllCaps, false);
                    i3 = 1;
                } else {
                    z2 = false;
                    z = false;
                }
                obtainStyledAttributes2.recycle();
            } else {
                z2 = false;
                z = false;
            }
            TypedArray obtainStyledAttributes3 = context.obtainStyledAttributes(attributeSet, f1411c, i, 0);
            if (obtainStyledAttributes3.hasValue(0)) {
                z = obtainStyledAttributes3.getBoolean(0, false);
            } else {
                i2 = i3;
            }
            obtainStyledAttributes3.recycle();
            if (i2 != 0) {
                m2599a(z);
            }
        }
    }

    void m2599a(boolean z) {
        this.f1412a.setTransformationMethod(z ? new C0245a(this.f1412a.getContext()) : null);
    }
}
