package android.support.v4.widget;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Paint;
import android.util.AttributeSet;
import android.view.ViewGroup.LayoutParams;
import android.view.ViewGroup.MarginLayoutParams;

/* renamed from: android.support.v4.widget.r */
public class C0079r extends MarginLayoutParams {
    private static final int[] f326e;
    public float f327a;
    boolean f328b;
    boolean f329c;
    Paint f330d;

    static {
        f326e = new int[]{16843137};
    }

    public C0079r() {
        super(-1, -1);
        this.f327a = 0.0f;
    }

    public C0079r(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.f327a = 0.0f;
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, f326e);
        this.f327a = obtainStyledAttributes.getFloat(0, 0.0f);
        obtainStyledAttributes.recycle();
    }

    public C0079r(LayoutParams layoutParams) {
        super(layoutParams);
        this.f327a = 0.0f;
    }

    public C0079r(MarginLayoutParams marginLayoutParams) {
        super(marginLayoutParams);
        this.f327a = 0.0f;
    }
}
