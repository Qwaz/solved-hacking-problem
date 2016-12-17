package android.support.v7.widget;

import android.content.Context;
import android.graphics.drawable.Drawable;
import android.support.v4.p006c.p007a.C0062a;
import android.support.v7.p015b.C0233b;

/* renamed from: android.support.v7.widget.p */
class C0299p extends ax implements C0258u {
    final /* synthetic */ C0294k f1587a;
    private final float[] f1588b;

    public C0299p(C0294k c0294k, Context context) {
        this.f1587a = c0294k;
        super(context, null, C0233b.actionOverflowButtonStyle);
        this.f1588b = new float[2];
        setClickable(true);
        setFocusable(true);
        setVisibility(0);
        setEnabled(true);
        setOnTouchListener(new C0300q(this, this, c0294k));
    }

    public boolean m2835c() {
        return false;
    }

    public boolean m2836d() {
        return false;
    }

    public boolean performClick() {
        if (!super.performClick()) {
            playSoundEffect(0);
            this.f1587a.m2828d();
        }
        return true;
    }

    protected boolean setFrame(int i, int i2, int i3, int i4) {
        boolean frame = super.setFrame(i, i2, i3, i4);
        Drawable drawable = getDrawable();
        Drawable background = getBackground();
        if (!(drawable == null || background == null)) {
            int width = getWidth();
            int height = getHeight();
            int max = Math.max(width, height) / 2;
            width = (width + (getPaddingLeft() - getPaddingRight())) / 2;
            height = (height + (getPaddingTop() - getPaddingBottom())) / 2;
            C0062a.m457a(background, width - max, height - max, width + max, height + max);
        }
        return frame;
    }
}
