package android.support.v4.widget;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.view.ViewGroup.LayoutParams;
import android.view.ViewGroup.MarginLayoutParams;

/* renamed from: android.support.v4.widget.b */
public class C0063b extends MarginLayoutParams {
    public int f312a;
    float f313b;
    boolean f314c;
    boolean f315d;

    public C0063b(int i, int i2) {
        super(i, i2);
        this.f312a = 0;
    }

    public C0063b(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.f312a = 0;
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, DrawerLayout.f270a);
        this.f312a = obtainStyledAttributes.getInt(0, 0);
        obtainStyledAttributes.recycle();
    }

    public C0063b(C0063b c0063b) {
        super(c0063b);
        this.f312a = 0;
        this.f312a = c0063b.f312a;
    }

    public C0063b(LayoutParams layoutParams) {
        super(layoutParams);
        this.f312a = 0;
    }

    public C0063b(MarginLayoutParams marginLayoutParams) {
        super(marginLayoutParams);
        this.f312a = 0;
    }
}
