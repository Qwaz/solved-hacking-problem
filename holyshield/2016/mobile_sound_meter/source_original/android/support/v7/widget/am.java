package android.support.v7.widget;

import android.content.Context;
import android.util.AttributeSet;
import android.widget.CheckedTextView;
import android.widget.TextView;

public class am extends CheckedTextView {
    private static final int[] f1295a;
    private ao f1296b;
    private bn f1297c;

    static {
        f1295a = new int[]{16843016};
    }

    public am(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 16843720);
    }

    public am(Context context, AttributeSet attributeSet, int i) {
        super(de.m2707a(context), attributeSet, i);
        this.f1297c = bn.m2593a((TextView) this);
        this.f1297c.m2598a(attributeSet, i);
        this.f1297c.m2595a();
        this.f1296b = ao.m2497a();
        dh a = dh.m2710a(getContext(), attributeSet, f1295a, i, 0);
        setCheckMarkDrawable(a.m2713a(0));
        a.m2714a();
    }

    protected void drawableStateChanged() {
        super.drawableStateChanged();
        if (this.f1297c != null) {
            this.f1297c.m2595a();
        }
    }

    public void setCheckMarkDrawable(int i) {
        if (this.f1296b != null) {
            setCheckMarkDrawable(this.f1296b.m2520a(getContext(), i));
        } else {
            super.setCheckMarkDrawable(i);
        }
    }

    public void setTextAppearance(Context context, int i) {
        super.setTextAppearance(context, i);
        if (this.f1297c != null) {
            this.f1297c.m2596a(context, i);
        }
    }
}
