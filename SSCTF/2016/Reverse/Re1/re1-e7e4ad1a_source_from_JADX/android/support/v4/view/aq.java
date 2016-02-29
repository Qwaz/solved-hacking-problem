package android.support.v4.view;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.view.ViewGroup.LayoutParams;

public class aq extends LayoutParams {
    public boolean f255a;
    public int f256b;
    float f257c;
    boolean f258d;
    int f259e;
    int f260f;

    public aq() {
        super(-1, -1);
        this.f257c = 0.0f;
    }

    public aq(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.f257c = 0.0f;
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, ViewPager.f199a);
        this.f256b = obtainStyledAttributes.getInteger(0, 48);
        obtainStyledAttributes.recycle();
    }
}
