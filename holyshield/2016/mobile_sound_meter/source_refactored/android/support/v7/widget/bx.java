package android.support.v7.widget;

import android.content.Context;
import android.content.res.TypedArray;
import android.support.v7.p015b.C0243l;
import android.util.AttributeSet;
import android.view.ViewGroup.LayoutParams;
import android.view.ViewGroup.MarginLayoutParams;

public class bx extends MarginLayoutParams {
    public float f1422g;
    public int f1423h;

    public bx(int i, int i2) {
        super(i, i2);
        this.f1423h = -1;
        this.f1422g = 0.0f;
    }

    public bx(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.f1423h = -1;
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, C0243l.LinearLayoutCompat_Layout);
        this.f1422g = obtainStyledAttributes.getFloat(C0243l.LinearLayoutCompat_Layout_android_layout_weight, 0.0f);
        this.f1423h = obtainStyledAttributes.getInt(C0243l.LinearLayoutCompat_Layout_android_layout_gravity, -1);
        obtainStyledAttributes.recycle();
    }

    public bx(LayoutParams layoutParams) {
        super(layoutParams);
        this.f1423h = -1;
    }
}
