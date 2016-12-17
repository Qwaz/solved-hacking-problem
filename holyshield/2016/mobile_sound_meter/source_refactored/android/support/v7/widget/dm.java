package android.support.v7.widget;

import android.content.Context;
import android.support.v7.p014a.C0210b;
import android.util.AttributeSet;
import android.view.ViewGroup.LayoutParams;
import android.view.ViewGroup.MarginLayoutParams;

public class dm extends C0210b {
    int f1529b;

    public dm(int i, int i2) {
        super(i, i2);
        this.f1529b = 0;
        this.a = 8388627;
    }

    public dm(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.f1529b = 0;
    }

    public dm(C0210b c0210b) {
        super(c0210b);
        this.f1529b = 0;
    }

    public dm(dm dmVar) {
        super((C0210b) dmVar);
        this.f1529b = 0;
        this.f1529b = dmVar.f1529b;
    }

    public dm(LayoutParams layoutParams) {
        super(layoutParams);
        this.f1529b = 0;
    }

    public dm(MarginLayoutParams marginLayoutParams) {
        super((LayoutParams) marginLayoutParams);
        this.f1529b = 0;
        m2736a(marginLayoutParams);
    }

    void m2736a(MarginLayoutParams marginLayoutParams) {
        this.leftMargin = marginLayoutParams.leftMargin;
        this.topMargin = marginLayoutParams.topMargin;
        this.rightMargin = marginLayoutParams.rightMargin;
        this.bottomMargin = marginLayoutParams.bottomMargin;
    }
}
