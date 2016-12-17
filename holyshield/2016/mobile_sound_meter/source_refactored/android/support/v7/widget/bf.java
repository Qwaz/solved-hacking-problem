package android.support.v7.widget;

import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import android.widget.SeekBar;

class bf extends bb {
    private static final int[] f1351b;
    private final SeekBar f1352c;

    static {
        f1351b = new int[]{16843074};
    }

    bf(SeekBar seekBar, ao aoVar) {
        super(seekBar, aoVar);
        this.f1352c = seekBar;
    }

    void m2542a(AttributeSet attributeSet, int i) {
        super.m2541a(attributeSet, i);
        dh a = dh.m2710a(this.f1352c.getContext(), attributeSet, f1351b, i, 0);
        Drawable b = a.m2717b(0);
        if (b != null) {
            this.f1352c.setThumb(b);
        }
        a.m2714a();
    }
}
