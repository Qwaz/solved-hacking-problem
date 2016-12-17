package android.support.v7.p014a;

import android.content.Context;
import android.content.res.TypedArray;
import android.support.v7.p015b.C0243l;
import android.util.AttributeSet;
import android.view.ViewGroup.LayoutParams;
import android.view.ViewGroup.MarginLayoutParams;

/* renamed from: android.support.v7.a.b */
public class C0210b extends MarginLayoutParams {
    public int f679a;

    public C0210b(int i, int i2) {
        super(i, i2);
        this.f679a = 0;
        this.f679a = 8388627;
    }

    public C0210b(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.f679a = 0;
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, C0243l.ActionBarLayout);
        this.f679a = obtainStyledAttributes.getInt(C0243l.ActionBarLayout_android_layout_gravity, 0);
        obtainStyledAttributes.recycle();
    }

    public C0210b(C0210b c0210b) {
        super(c0210b);
        this.f679a = 0;
        this.f679a = c0210b.f679a;
    }

    public C0210b(LayoutParams layoutParams) {
        super(layoutParams);
        this.f679a = 0;
    }
}
