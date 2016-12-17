package android.support.v7.widget;

import android.content.Context;
import android.support.v7.p015b.C0233b;
import android.util.AttributeSet;
import android.widget.SeekBar;

public class be extends SeekBar {
    private bf f1349a;
    private ao f1350b;

    public be(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, C0233b.seekBarStyle);
    }

    public be(Context context, AttributeSet attributeSet, int i) {
        super(context, attributeSet, i);
        this.f1350b = ao.m2497a();
        this.f1349a = new bf(this, this.f1350b);
        this.f1349a.m2542a(attributeSet, i);
    }
}
